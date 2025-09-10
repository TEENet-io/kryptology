# GG20 Threshold ECDSA Implementation

## 概述

本包实现了基于 [Gennaro & Goldfeder 2020](https://eprint.iacr.org/2020/540.pdf) 论文的 t-of-n 门限 ECDSA 签名协议，支持可识别中止功能。

> ⚠️ **重要提示**: GG20 协议的作者已声明该协议已过时，不应再使用。建议使用更新的 CGGMP 协议或其他替代方案。详见 [https://eprint.iacr.org/2020/540.pdf](https://eprint.iacr.org/2020/540.pdf)

## 主要特性

- **门限签名**: 支持 t-of-n 门限签名，只需 t 个参与方即可生成有效签名
- **多种密钥生成方式**:
  - 可信分发者模式 (Trusted Dealer)
  - 分布式密钥生成 (DKG)
  - 密钥重分享 (Resharing)
- **完整的零知识证明**: 包含 Range、PDL、CDL、MtA 等多种证明
- **可识别中止**: 能够识别恶意参与方导致的协议中止
- **生产就绪**: 包含完整的测试套件和基准测试

## 项目结构

```
gg20/
├── participant/     # 核心参与方逻辑
│   ├── participant.go         # 基础参与方和签名者结构
│   ├── dkg_round1-3.go       # DKG协议实现（3轮）
│   ├── round1-6.go           # 签名协议实现（6轮）
│   └── *_test.go             # 测试文件
├── dealer/         # 可信分发者实现
│   ├── dealer.go             # 密钥生成和分发
│   └── share.go              # 份额数据结构
├── resharing/      # 密钥重分享协议
│   ├── participant.go        # 重分享参与方
│   └── round1-3.go          # 重分享协议轮次
└── proof/          # 零知识证明
    ├── mta.go               # MtA协议证明
    ├── pdl.go               # PDL证明
    ├── cdl.go               # CDL证明
    └── util.go              # 工具函数
```

## 快速开始

### 1. 使用可信分发者生成密钥

```go
import (
    "github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/dealer"
    "github.com/TEENet-io/kryptology/pkg/core/curves"
)

// 创建分发者
d, err := dealer.NewDealer(
    3,                          // 门限值
    5,                          // 总参与方数
    curves.K256(),              // 椭圆曲线
)

// 生成份额
secretShares, err := d.Deal()

// 分发给参与方
for id, share := range secretShares {
    // 安全地发送 share 给参与方 id
}
```

### 2. 分布式密钥生成 (DKG)

```go
import (
    "github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/participant"
)

// 初始化DKG参与方
dkgParticipant := participant.NewDkgParticipant(
    participantID,
    curves.K256(),
)

// 执行DKG第1轮
round1Out, err := dkgParticipant.DkgRound1(threshold, total)
// 广播 round1Out 给所有参与方

// 执行DKG第2轮
round2Bcast, round2P2P, err := dkgParticipant.DkgRound2(round1Outputs)
// 广播 round2Bcast，点对点发送 round2P2P

// 执行DKG第3轮
psfProof, err := dkgParticipant.DkgRound3(witnesses, shares)

// 执行DKG第4轮（最终）
dkgResult, err := dkgParticipant.DkgRound4(psfProofs)
```

### 3. 门限签名生成

```go
// 从DKG或分发者结果创建签名者
signer, err := participant.NewSigner(
    participantData,
    cosignerIDs,
)

// 准备消息哈希
messageHash := sha256.Sum256([]byte("message to sign"))

// 执行签名协议（6轮）
// 第1轮：承诺和范围证明
round1Bcast, round1P2P, err := signer.SignRound1()

// 第2轮：MtA第一阶段
round2P2P, err := signer.SignRound2(round1Broadcasts, round1P2Ps)

// 第3轮：MtA完成
round3Bcast, err := signer.SignRound3(round2P2Ps)

// 第4轮：Delta聚合
round4Bcast, err := signer.SignRound4(round3Broadcasts)

// 第5轮：R值计算
round5Bcast, round5P2P, err := signer.SignRound5(round4Broadcasts)

// 第6轮：签名生成
round6Bcast, err := signer.SignRound6Full(
    messageHash[:],
    round5Broadcasts,
    round5P2Ps,
)

// 输出最终签名
signature, err := signer.SignOutput(round6Broadcasts)
```

### 4. 密钥重分享

```go
import (
    "github.com/TEENet-io/kryptology/pkg/tecdsa/gg20/resharing"
)

// 配置重分享参数
config := &resharing.Config{
    OldThreshold: 3,
    NewThreshold: 4,
    OldParties: []uint32{1, 2, 3, 4, 5},
    NewParties: []uint32{1, 2, 3, 6, 7, 8},
}

// 创建重分享参与方（老参与方）
resharer := resharing.NewReshareParticipant(
    participantID,
    config,
    oldShare,           // 现有份额
    curve,
)

// 执行重分享协议
// ... (类似DKG的多轮协议)
```

## 协议详解

### 1. 签名协议流程 (6轮)

GG20签名协议是一个6轮的交互式协议，实现了门限ECDSA签名的安全生成：

#### Round 1: 承诺和范围证明生成
```
每个签名者 i 执行:
1. 生成随机数: k_i ← Z_q (用于签名的nonce)
2. 生成掩码值: γ_i ← Z_q (用于MtA协议的掩码)
3. 计算承诺点: Γ_i = g^γ_i (掩码值的椭圆曲线点)
4. 创建承诺: (C_i, D_i) = Commit(Γ_i) (使用SHA256承诺方案)
5. Paillier加密: c_i = Enc_pki(k_i; r_i) (加密nonce值)
6. 生成范围证明: π^Range1_i 证明 k_i ∈ [-q^3, q^3]

广播: (C_i, c_i, π^Range1_i)
存储: (k_i, γ_i, Γ_i, D_i, c_i, r_i)
```

**安全目的**: 
- 承诺机制防止恶意参与者在看到其他人的值后修改自己的值
- 范围证明确保加密的值在合理范围内，防止溢出攻击
- Paillier加密允许同态计算，实现MtA协议

#### Round 2: MtA协议第一阶段
```
每个签名者 i 对每个其他签名者 j 执行:
1. 验证范围证明: Verify(π^Range1_j) 
2. MtA-γ响应: 
   - 计算: c^γ_ji = c_j * γ_i + Enc_pkj(β_ji)
   - 生成证明: π^Range2_ji 证明 β_ji 的范围
3. MtA-w响应:
   - 计算: c^w_ji = c_j * w_i + Enc_pkj(ν_ji)  
   - 生成证明: π^Range3_ji 证明 ν_ji 的范围
   (其中 w_i 是签名者的私钥份额)

P2P发送给 j: (c^γ_ji, c^w_ji, π^Range2_ji, π^Range3_ji)
存储: (β_ji, ν_ji) 用于后续计算
```

**MtA协议原理**: 
- 将乘法秘密分享转换为加法秘密分享
- 利用Paillier的同态性质: Enc(a) * b = Enc(a*b)
- 确保 k_i * γ_j 被安全地分割为两个加法份额

#### Round 3: MtA完成和δ/σ计算
```
每个签名者 i 执行:
1. 验证所有MtA证明: Verify(π^Range2_ji, π^Range3_ji)
2. 解密收到的密文:
   - α_ij = Dec_ski(c^γ_ij) 
   - μ_ij = Dec_ski(c^w_ij)
3. 计算δ份额:
   δ_i = k_i * γ_i + Σ(α_ij + β_ji) for all j≠i
4. 计算σ份额:
   σ_i = k_i * w_i + Σ(μ_ij + ν_ji) for all j≠i

广播: δ_i
存储: σ_i 用于最终签名
```

**关键计算**:
- δ = Σδ_i = (Σk_i) * (Σγ_i) = k * γ (总的掩码乘积)
- σ = Σσ_i = (Σk_i) * (Σw_i) = k * w (nonce与私钥的乘积)

#### Round 4: Delta聚合
```
每个签名者 i 执行:
1. 收集所有δ_j值
2. 计算总和: δ = Σδ_j for all j
3. 验证δ ≠ 0 (否则协议失败)
4. 打开承诺: 发送 D_i (Round 1的承诺开启值)

广播: D_i
存储: δ
```

**安全检查**: 如果δ = 0，说明存在问题，协议必须重启

#### Round 5: R值计算和PDL证明
```
每个签名者 i 执行:
1. 验证承诺: 对所有j, 检查 Commit(Γ_j) ?= (C_j, D_j)
2. 计算总Gamma: Γ = Π Γ_j = g^(Σγ_j) = g^γ
3. 计算R点: R = Γ^(δ^-1) = g^(γ/δ) = g^(γ/(k*γ)) = g^(1/k)
4. 提取r值: r = R.x (签名的r分量)
5. 计算个人R份额: R̄_i = R^k_i
6. 生成PDL证明: π^PDL_i 证明 log_g(R̄_i) = k_i

广播: R̄_i
P2P发送: π^PDL_i
```

**PDL证明的作用**: 证明每个参与者正确使用了他们在Round 1承诺的k_i值

#### Round 6: 最终签名生成
```
每个签名者 i 执行:
1. 验证所有PDL证明: Verify(π^PDL_j) for all j
2. 验证R̄一致性: Π R̄_j ?= R^(Σk_j) = R^k
3. 计算消息哈希: m = H(message)
4. 计算签名份额: s_i = m * k_i + r * σ_i
   展开: s_i = m * k_i + r * (k_i * w_i + Σ(μ_ij + ν_ji))

广播: s_i
```

**最终签名组合**:
```
s = Σs_i = m * (Σk_i) + r * (Σσ_i)
    = m * k + r * k * w
    = k * (m + r * w)
    = k * (m + r * x)  (其中 x 是私钥)

因此 s * k^-1 = m + r * x，符合ECDSA签名方程
最终签名: (r, s)
```

### 2. DKG协议流程 (4轮)

分布式密钥生成允许参与者在没有可信第三方的情况下共同生成密钥：

#### DKG Round 1: 初始化和承诺
```
每个参与者 i 执行:
1. 生成随机多项式:
   f_i(x) = u_i + a_i1*x + ... + a_it*x^t (mod q)
   其中 u_i 是随机选择的常数项
2. 使用Feldman VSS:
   - 计算份额: x_ij = f_i(j) for all j
   - 生成承诺: V_ik = g^a_ik for k = 0...t
3. 承诺阶段: (C_i, D_i) = Commit(V_i0, ..., V_it)
4. 生成Paillier密钥对: (pk_i, sk_i) ← PaillierKeyGen(2048)
5. 生成安全素数: P_i = 2p_i + 1, Q_i = 2q_i + 1
6. 计算: N_i = P_i * Q_i, h1_i = rand(Z*_Ni), h2_i = rand(Z*_Ni)
7. 生成CDL证明: 
   - π1_i = CDLProve(h1_i, P_i, Q_i, N_i)
   - π2_i = CDLProve(h2_i, P_i, Q_i, N_i)

广播: (C_i, pk_i, N_i, h1_i, h2_i, π1_i, π2_i)
秘密保存: (D_i, x_i1...x_in, sk_i, P_i, Q_i)
```

**Feldman VSS的作用**: 允许验证份额的正确性，同时保持秘密的隐私

#### DKG Round 2: 份额分发
```
每个参与者 i 执行:
1. 验证CDL证明: 对所有j≠i, 验证 π1_j, π2_j
2. 打开承诺: 发送 D_i
3. P2P发送份额: 发送 x_ij 给参与者 j

广播: D_i
P2P发送: x_ij (加密通道)
```

#### DKG Round 3: 份额验证和公钥构建
```
每个参与者 i 执行:
1. 验证承诺: 检查 Commit(V_j0...V_jt) ?= (C_j, D_j)
2. 验证收到的份额: 
   g^x_ji ?= Π(V_jk)^(i^k) for k=0...t
3. 计算自己的最终份额:
   w_i = Σx_ji (所有j的份额之和)
4. 计算公共参数:
   - 全局公钥: Y = Π V_j0 = g^(Σu_j) = g^x
   - 公开份额: Y_j = g^w_j for all j
5. 生成PSF证明: π^PSF_i 证明 N_i 的正确构造

广播: π^PSF_i
```

**公钥生成原理**: Y = g^(Σu_j) 其中每个u_j是参与者j的多项式常数项

#### DKG Round 4: 最终确认
```
每个参与者 i 执行:
1. 验证所有PSF证明: Verify(π^PSF_j) for all j
2. 输出DKG结果:
   - 私钥份额: w_i
   - 全局公钥: Y
   - 公开份额: {Y_j}
   - Paillier密钥: {pk_j, sk_i}
   - 证明参数: {N_j, h1_j, h2_j}
```

### 3. 重分享协议流程 (3轮)

重分享协议允许在保持相同ECDSA公钥的情况下改变门限值和参与者集合：

#### Resharing Round 1: 份额生成和分发
```
每个老参与者 i (拥有份额 w_i) 执行:
1. 计算Lagrange系数:
   λ_i = Π(0 - j)/(i - j) for all j ∈ OldParties, j≠i
   (这确保Σλ_i * w_i = x，即原始私钥)
2. 调整份额: w'_i = λ_i * w_i
3. 生成新多项式:
   f_i(x) = w'_i + a_i1*x + ... + a_i(t'-1)*x^(t'-1)
   (常数项是调整后的份额，t'是新门限)
4. 生成Feldman承诺:
   C_ik = g^a_ik for k = 0...t'-1
5. 计算新份额:
   s_ij = f_i(j) for all j ∈ NewParties

发送给新参与者j: (s_ij, {C_ik})
```

**关键点**: 使用Lagrange插值确保所有老参与者的贡献正确重构原始私钥

#### Resharing Round 2: Paillier密钥交换
```
所有参与者(新老) i 执行:
1. 如果是新参与者，生成Paillier密钥对
2. 广播自己的Paillier公钥

广播: pk_i
如果是老参与者，同时广播: KeyGenType (保留原有的密钥生成类型)
```

#### Resharing Round 3: 份额组合和验证
```
每个新参与者 j 执行:
1. 验证收到的份额(使用Feldman承诺):
   g^s_ij ?= Π(C_ik)^(j^k) for k=0...t'-1
2. 组合份额:
   w'_j = Σs_ij (来自所有老参与者i)
3. 计算公开份额:
   Y_j = g^w'_j
4. 验证公钥保持不变:
   Y ?= g^x (原始公钥)

输出:
- 新私钥份额: w'_j  
- 公开份额: Y_j
- Paillier密钥对
```

**验证原理**: 
```
Σw'_j = Σ(Σs_ij) = Σ(Σf_i(j)) = Σw'_i = Σ(λ_i * w_i) = x
```
因此新份额正确重构原始私钥。

### 4. 零知识证明详解

#### Range Proof (范围证明)
- **目的**: 证明Paillier密文中的明文在指定范围内
- **应用**: Round 1-3中防止恶意的大数值攻击
- **构造**: 基于Σ-protocol和Fiat-Shamir变换

#### PDL Proof (离散对数乘积证明)
- **目的**: 证明 log_g(A) * log_h(B) = log_g(C)
- **应用**: Round 5中验证R̄_i的正确性
- **安全性**: 基于DDH假设

#### CDL Proof (复合离散对数证明)
- **目的**: 证明知道N = P*Q的因子分解
- **应用**: DKG中验证Paillier模数的正确生成
- **防护**: 防止恶意构造的模数

#### MtA Protocol (乘法到加法转换)
- **目的**: 将乘法秘密分享 a*b 转换为加法分享 α + β = a*b
- **核心**: 利用Paillier同态性质
- **安全性**: 基于Paillier加密的语义安全性

### 5. 安全特性

- **可识别中止**: 通过零知识证明，可以识别导致协议失败的恶意参与者
- **前向安全**: 每次签名使用新的随机数k，泄露不影响其他签名
- **抗重放攻击**: 每轮都有唯一的承诺和随机数
- **抗偏差攻击**: 承诺机制防止根据他人值调整自己的输入
- **门限安全**: 少于t个参与者无法生成签名或恢复私钥

## 性能优化

### 测试模式

设置环境变量 `TEST_FAST_ECDSA` 以使用较小的密钥大小加速测试：

```bash
export TEST_FAST_ECDSA=1
go test ./...
```

### 并行执行

- DKG轮次可以并发执行
- 多个证明可以批量验证
- 签名轮次支持并行处理

## 基准测试

运行基准测试：

```bash
cd participant
go test -bench=. -benchmem
```

示例结果（M1 Pro）：

```
BenchmarkDkg_P256_2of3-10         50    23456789 ns/op    1234567 B/op    12345 allocs/op
BenchmarkDkg_P256_3of5-10         30    45678901 ns/op    2345678 B/op    23456 allocs/op
BenchmarkSign_P256_2of3-10       100    12345678 ns/op     567890 B/op     5678 allocs/op
```

## 数据结构

### 核心结构体

```go
// 参与方基础结构
type Participant struct {
    Share dealer.Share           // 从分发者获得的份额
    sk    *paillier.SecretKey   // Paillier私钥
}

// 签名者结构
type Signer struct {
    sk              *paillier.SecretKey
    share           *v1.ShamirShare
    publicSharesMap map[uint32]*dealer.PublicShare
    id              uint32
    threshold       uint
    PublicKey       *curves.EcPoint
    Curve           elliptic.Curve
    Round           uint
    state           *state
}

// DKG参与方
type DkgParticipant struct {
    Participant
    round      uint
    Curve      elliptic.Curve
    id         uint32
    // DKG特定状态...
}
```

### 消息类型

```go
// 签名轮次消息
type Round1Bcast struct {
    Identifier uint32
    C          core.Commitment
    Proof      *proof.RangeProof
}

type Round1P2PSend struct {
    C *paillier.Ciphertext
}

// DKG轮次消息
type DkgRound1Bcast struct {
    Identifier uint32
    Ci         core.Commitment
    Pki        *paillier.PublicKey
    H1i, H2i   *big.Int
    Proof1i    *proof.CdlProof
}
```

## 错误处理

所有函数都返回详细的错误信息：

```go
if err != nil {
    switch err {
    case internal.ErrInvalidRound:
        // 轮次不匹配
    case internal.ErrNilArguments:
        // 空参数
    default:
        // 其他错误
    }
}
```

## 安全注意事项

1. **密钥存储**: 私钥份额应安全存储，建议使用硬件安全模块(HSM)
2. **通信安全**: 所有通信应通过安全信道（如TLS）
3. **参数验证**: 始终验证输入参数的有效性
4. **随机数生成**: 使用密码学安全的随机数生成器
5. **证明验证**: 不要跳过任何零知识证明的验证步骤

## 依赖项

- `github.com/TEENet-io/kryptology/pkg/core`: 核心密码学原语
- `github.com/TEENet-io/kryptology/pkg/core/curves`: 椭圆曲线实现
- `github.com/TEENet-io/kryptology/pkg/paillier`: Paillier加密
- `github.com/TEENet-io/kryptology/pkg/sharing/v1`: Shamir/Feldman秘密分享

## 测试

运行所有测试：

```bash
# 快速测试
go test ./... -short

# 完整测试（包括长时间运行的测试）
go test ./...

# 特定测试
go test ./participant -run TestDkg
go test ./resharing -run TestResharing

# 覆盖率报告
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 许可证

本项目采用 Apache-2.0 许可证 - 详见 [LICENSE](LICENSE) 文件

## 参考文献

1. [GG20] Rosario Gennaro and Steven Goldfeder. "One Round Threshold ECDSA with Identifiable Abort." IACR Cryptology ePrint Archive 2020 (2020): 540.
2. [GG18] Rosario Gennaro and Steven Goldfeder. "Fast multiparty threshold ECDSA with fast trustless setup." ACM CCS 2018.
3. [Feldman VSS] Paul Feldman. "A practical scheme for non-interactive verifiable secret sharing." FOCS 1987.
4. [Shamir SS] Adi Shamir. "How to share a secret." Communications of the ACM 22.11 (1979): 612-613.

## 联系方式

- 项目主页: [https://github.com/TEENet-io/kryptology](https://github.com/TEENet-io/kryptology)
- 问题追踪: [GitHub Issues](https://github.com/TEENet-io/kryptology/issues)