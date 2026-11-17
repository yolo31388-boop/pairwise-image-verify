# pairwise-image-verify

镜像仓库一开签名验证，供应链门禁就误放：只检查 cosign 签名存在，没有绑定到 digest，tag 被覆盖后旧签名还能过；attestation 的 predicateType 不校验，SBOM 和 provenance 可以互换；签名者身份只匹配邮箱前缀，任何同名账号都能签；TUF 元数据过期没有拒绝，离线回滚攻击可过；多架构 manifest list 只验一个子 manifest。supplychain/image_verify.py 是核心，tests/test_image_verify.py 15个红。要修的是：digest 绑定；predicate 类型；签名者精确；TUF 时效；全子镜像验证。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
