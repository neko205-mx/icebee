// sign.go — Ed25519 指令签名与验证
//
// Admin 用私钥对每条任务签名，节点用公钥验证。
// 签名随任务在 P2P 中继传播，relay 节点同样验证，无法伪造。
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ── 节点侧：公钥缓存 ─────────────────────────────────────────────

var (
	adminPubKeyMu sync.RWMutex
	adminPubKey   ed25519.PublicKey // 从 Worker 响应中获取并缓存
)

// SetAdminPubKey 更新缓存的 Admin 公钥（hex 编码）。
func SetAdminPubKey(hexKey string) error {
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("无效的公钥: %w", err)
	}
	adminPubKeyMu.Lock()
	adminPubKey = ed25519.PublicKey(b)
	adminPubKeyMu.Unlock()
	return nil
}

// VerifyTask 验证任务签名。task 为 Worker 下发的原始 map。
// 签名位于 task["body"]["_sig"]，摘要为 body（不含 _sig）的 SHA256。
// 若无公钥（节点尚未收到）则放行，避免首次心跳卡死。
func VerifyTask(task map[string]interface{}) error {
	adminPubKeyMu.RLock()
	pub := adminPubKey
	adminPubKeyMu.RUnlock()

	if pub == nil {
		// 尚未收到公钥，暂时放行（首次启动宽限）
		logf("[sign] 尚未获取 adminPubKey，跳过验证\n")
		return nil
	}

	body, _ := task["body"].(map[string]interface{})
	if body == nil {
		return errors.New("任务缺少 body 字段")
	}

	sigHex, _ := body["_sig"].(string)
	if sigHex == "" {
		return errors.New("任务缺少签名字段 body._sig")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("签名格式错误: %w", err)
	}

	digest := bodyDigest(body)
	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("签名验证失败，拒绝执行")
	}
	return nil
}

// bodyDigest 计算 body 的规范摘要（排除 _sig 字段本身）。
func bodyDigest(body map[string]interface{}) []byte {
	cp := make(map[string]interface{}, len(body))
	for k, v := range body {
		if k != "_sig" {
			cp[k] = v
		}
	}
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	return sum[:]
}
