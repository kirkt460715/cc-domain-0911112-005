# trialvault 数据接入工作台

保留现有领域校验、持久化与操作入口。Python 3.11 标准库和 SQLite；运行时无需下载依赖。测试覆盖已有领域行为、错误路径和恢复。本地联调材料不会自动采集到业务库。

## 本地运行

    python3 -m compileall -q trialvault
    python3 -m unittest discover -s tests -v
    python3 -m trialvault demo

## 容器运行

    docker build -t local/trialvault .
    docker run --rm --network none local/trialvault

构建时准备基础镜像，正式运行不下载。run_checks.sh 是完整的测试、编译检查及实际产品演示入口，正常在 90 秒内结束。每次演示使用临时数据或内存库，不改写源样本。

## 采集联调

fixtures 中提供目录投递或网页原始样本，复制到临时目录后联调。

原有操作参数可通过 python3 -m trialvault --help 查询。

## 仪器投递接入

生产端先写数据文件，再将清单原子改名为 manifest.ready。扫描动作只认
manifest.ready：未出现的目录报告为 pending（尚未传完），出现后才校验成员
的长度、摘要、行数与契约，失败组隔离为 quarantined 并记录原因，正式数据
继续用旧版，同目录其他完整批次照常登记。同一投递号重复扫描幂等复用，
同号换内容必须隔离；投递目录只读，任何结果都不删原文件。复制期间被替换
的成员判为 unstable，下轮扫描自动重试；登记提交后未归档便重启的组在下次
扫描时恢复，不会重复登记。

    {"action": "deliveries_scan", "root": "incoming"}
    {"action": "deliveries"}
    {"action": "delivery", "id": "lab-delivery-01"}

扫描根目录本身含 manifest.ready 时按单组处理，否则每个含清单的子目录各算
一组。演练：把 fixtures/dropbox 复制到临时目录，先只放部分文件扫描，补齐
后再扫，最后改一行 manifest 内容（同号换内容）观察隔离。
