# 改动说明（对照原论文）

本次重构以论文第 II-A、III-A 节的角色定义为准：**Authority 持有 msk，数据拥有者持有 E_T，云端只做 CTUpdate，用户只持有自己的 sk_A**。采用方案 A（数据拥有者在本地加密），不实现根节点更新（RootEtOR / RootEtAND / RootEtThreshold）。

## 1. 安全问题修复

| # | 问题（旧代码） | 后果 | 修复 | 论文依据 |
|---|---|---|---|---|
| 1 | `encrypt()` 把随机数 `s_map` 写进 `CT["_debug"]` 并上传 | 任何人拿到 v1.json 和 mpk 就能算 `K = C0 / Z^{s_r}` 解出明文 | `encrypt()` 返回 `(CT, E_T)`；E_T 只写入数据拥有者本地 `owner_secrets/<id>/E_T_v<N>.json` | Enc 输出 (ct_T, E_T)，“stores the random numbers E_T locally” |
| 2 | `keygen()` 写入 `SK["_meta"] = {r, alpha}` | 用户拿到主密钥 α | 删除 `_meta` | sk_A = {w^{(r−1)/β}, sk_t} |
| 3 | `keygen()` 为编号 1…4ℓ **全部**生成私钥分量，权限只靠命令行 `--attrs` | 持有 attA 私钥的用户谎报 attB,attC 就能解开 `(attB AND attC)`（已实测复现） | 只为 ρ(A) ∪ U′ 生成；属性集写在私钥里，解密时从私钥读取，命令行不再接受 `--attrs` | sk_t, t ∈ A ∪ U′ |
| 4 | 私钥分量含自身的 h_t^{r q(t)} | 与论文不符，多给了用户信息 | 去掉；解密改为 a_t · Π_{t′≠t} c_t[t′] | sk_t 中 “…h_{t−1}, h_{t+1}…” |
| 5 | ρ（属性名→编号）每次从策略字符串推导 | 同一属性在不同策略里编号不同；签发私钥还必须提供 `--policy` | Setup 时用 `--universe` 固定 ρ，写入 mpk 公开 | ρ(att_i) = i 在 Setup 中定义 |
| 6 | 云端脚本读取同时含 mpk 和 msk 的 `ta_setup.json` | 云端拿到 msk | 拆成 `mpk.json` / `msk.json`；非 Authority 角色加载到含 msk 的文件直接报错 | Authority 不与任何方共谋，msk 只在 Authority |
| 7 | 云端（Lambda）执行加密 | 云端看到明文和 E_T，与“诚实但好奇”假设冲突 | 加密移到数据拥有者本地 `owner_encrypt.py` | Data owner 负责加密并上传 |
| 8 | 云端从密文中取 E_T 执行 UPKeyGen | 同 1 | UPKeyGen 移到数据拥有者 `owner_upkeygen.py`，只上传 tk | UPKeyGen 输入 E_T，由数据拥有者执行 |
| 9 | 策略更新后旧版本 v1 仍可下载 | 收紧策略形同虚设 | CTUpdate 后默认删除 vN 和已用的 tk（`--keep-history` / `KEEP_HISTORY=1` 可保留，仅用于演示） | CTUpdate 输出 ct_T′ 替换 ct_T |

## 2. 正确性修复

| 问题 | 修复 |
|---|---|
| 单属性策略 `attA` 被改写成 `(attA AND attA)`，阈值 2 但叶子去重后只剩 1 个，永远解不开 | 单属性改为 1-of-1 门 `(1, attA)`；同一门下重复属性直接报错 |
| 解密、更新时重新解析策略字符串并按 DFS 顺序给子树编号，Attributes2New 后编号可能错位；新叶子分量存成 `ct_new_leaf`，解密时根本没用到 | 密文中显式保存树结构 `tree`（标签、阈值、叶子、有序的子门列表），解密与更新都只读这个结构；子门分量按标签存放在 `ct_child` 中 |
| Attributes2New 从旧 E_T 中按新子树名取 s_t（可能取到别的节点的 s，或 KeyError） | 数据拥有者新选 s_t，并写入 E_T_v(N+1) |
| `A OR B OR C` 被解析成嵌套的二叉门 | 同类运算链展平为 1-of-n / n-of-n 门 |
| tokenizer 遇到 `-` 等字符死循环 | 直接报错 |
| `client_decrypt.py` 文档写 AAD=policy，代码用 object_id | 统一为 object_id |

## 3. 策略更新流程

```
数据拥有者 owner_upkeygen.py                       云端 app.py / cloud_update.py
  读 vN（公开的树结构）+ 本地 E_T_vN
  plan_update(): 自动识别要改的那一个门
      → Attributes2Existing / Attributes2New
  UPKeyGen → tk
  上传 updates/<id>/tk_vN.json  ───S3 事件───▶  CTUpdate(ct_vN, tk) → v(N+1)
  本地保存 E_T_v(N+1)                              c_aes 原样保留；删除 vN 与 tk
```

* `--mode`、`--target-subtree` 变成可选的断言参数：不填会自动识别，填了会和识别结果比对。
* 不支持的情况会给出明确错误：新旧策略相同、一次改动多个门、删除一个门、新门内含嵌套门、根节点更新。
* 重复的 S3 事件（同一个 tk 被投递两次）直接跳过；tk 尚未被云端处理时，再次生成需要加 `--force`。

**一处工程补充（论文未覆盖）**：论文更新时保留 ct_{j,i+2} 不变，但它的下标 2ℓ − t_j + i 依赖 t_j。如果某个门**本身有子门**，并且这次更新**改变了它的阈值**，旧分量就对不上了（Ω′_j 还可能和它重叠）。这种情况下数据拥有者会在 tk 里重新签发这几个子门分量（`tk_children`）。其余情况（包括论文图 3、图 4 的两个例子）tk 仍是常数大小。

## 4. 保留的实现选择（已在文档中注明）

* 默认属性集 U′ 取 {ℓ+1 … 4ℓ}（论文为 {ℓ+1 … 2ℓ}），这样一个门的子门数量可以超过它的阈值。这些下标只用作 Ω_j 和子门位置，从不对应真实属性。
* 曲线仍用 SS512，与论文实验一致（约 80 位安全强度，charm 会给出警告）。

## 5. 文件对照

| 旧文件 | 新文件 / 去向 |
|---|---|
| `ta_local.py`（算法 + TA 命令行） | `abe_core.py`（算法）+ `ta_local.py`（只保留 TA 命令行） |
| `lambda_encrypt.py`（云端加密） | `owner_encrypt.py`（数据拥有者本地加密） |
| `cloud_update.py`（UPKeyGen + CTUpdate） | `owner_upkeygen.py`（UPKeyGen）+ `cloud_update.py`（只做 CTUpdate） |
| `app.py`（只做 AES 加密，密钥直接丢弃） | `app.py`（S3 触发 CTUpdate） |
| `object_store.py`（本地 JSON） | `object_store.py`（本地目录或 S3，同一套 key 布局） |
| — | `hybrid.py`（KDF + AES-GCM） |
| `abe_project_local_client_and_lambda.py` | 删除（旧版单文件，含把用户私钥发给云端的 `cloud_decrypt_for_user`） |
| `crypto_core.py` | 删除（测试改为直接调用各角色函数，不再从标准输出里“取最后一行”） |
| `tests/test_*.py`（3 个，默认跳过） | `test_core.py`、`test_security.py`、`test_policy_update.py`、`test_lambda.py`（moto 模拟 S3）、`test_cli.py`，共 47 个；检测到 charm 就自动运行 |
| `tests/bench_local.py`（导入不存在的 `ade_abe`） | 可运行，覆盖论文三个实验维度 |
| `docker/Dockerfile` | COPY 路径改为从项目根目录构建；charm 固定到 v0.63；加入 tests |
| `requirements.txt` | 去掉没用到的 `pyparsing`；dev 依赖加 `moto[s3]` |

## 6. 数据格式变化（与旧版不兼容）

旧版生成的 `ta_setup.json`、`user_sk.json` 和 `store/` 需要重新生成：新 mpk 中带有全局 ρ，密文带 `scheme: "pu-cp-abe/2"` 和 `tree`，旧格式的密文会被拒绝解密。
