# Integration harnesses VPS

Các harnesses này được chuyển từ deployment cũ, dùng
[templates](../../templates/compose.yaml.j2), [profiles](../../files/profiles/)
và [integration files](../../files/) của Ansible. `compose_fixture.py` render
model bằng Ansible/Compose; không duy trì manifest test trùng với production.
Python 3.11+, dependencies ở [requirements](../../requirements.txt), Docker và
image test đã build/pull phù hợp runtime. Chạy từ root repository, dùng controller
venv để có Ansible/PyYAML:

```sh
deploy/ansible/.venv/bin/python deploy/ansible/tests/integration/resource-profiles.py --image <TEST_IMAGE>
OPENWAF_TEST_IMAGE=<TEST_IMAGE> deploy/ansible/.venv/bin/python deploy/ansible/tests/integration/dependencies-smoke.py
OPENWAF_TEST_IMAGE=<TEST_IMAGE> deploy/ansible/.venv/bin/python deploy/ansible/tests/integration/startup-smoke.py --external-network
deploy/ansible/.venv/bin/python deploy/ansible/tests/integration/provider-bootstrap.py
deploy/ansible/.venv/bin/python deploy/ansible/tests/integration/dns-simulation.py --acme
```

| Harness | Phạm vi |
| --- | --- |
| `resource-profiles.py` | Năm profile, caps/headroom/fingerprint, native resource validator offline và từ chối profile sai |
| `dependencies-smoke.py` | Native init, ClickHouse/CrowdSec persistence, collector inventory/restart, runtime caps và missing-key guard |
| `startup-smoke.py` | Init + PostgreSQL + gateway HTTPS với private CA, setup/login, Certificates/provider và restart; tùy chọn external network |
| `provider-bootstrap.py` | Transactional provider import/ownership trên PostgreSQL container riêng |
| `dns-simulation.py`, `acme_simulation.py` | Native HTTP caller qua [Postman simulation](../../../../postman/simulations/admin-dns.sim.yaml), Pebble CA và TXT fixture; issuance/renewal/restart/cancellation |

`resource-profiles` không start application services hoặc gọi provider.
Dependency smoke chỉ start các service test đã chọn, namespace holder thay gateway
và không publish ports. Nó dùng một volume fixture riêng làm filesystem Linux
POSIX để backing **bind sources**, kể cả trên Docker Desktop; đây không phải
application named volumes hoặc workflow migrate production. Containers được dừng
trước khi dọn fixture storage. Không chạy harness với project/volumes của instance thật.

Startup smoke hiện đọc trực tiếp private fixture files trên host; chạy trên
Linux filesystem có chmod/chown đúng UID 10001/1001. macOS shared filesystem
của Docker Desktop không chứng minh ownership đó. DNS/provider harnesses cần Rust
và native OpenSSL dependencies; DNS cần Postman CLI >=1.70 và OpenSSL, `--acme`
cần Docker/Pebble. Provider runner dùng PostgreSQL local, DNS runner dùng mocks
và private CA, không cần token thật và không ghi DNS công cộng.

Giữ [báo cáo lịch sử](../../../../docs/admin-startup-bootstrap.md) nguyên trạng;
xem [mapping paths](../../docs/legacy-paths.md) và
[kết quả kiểm tra mới](../../../../docs/evidence/deploy-cleanup.md). Pass local không thay nghiệm thu public
Cloudflare/Let's Encrypt, clean restore, capacity hoặc full VPS provisioning.
