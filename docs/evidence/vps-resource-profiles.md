# VPS resource profiles — kiểm chứng local 2026-11-02

Phạm vi: năm profile `2c4g`, `4c8g`, `8c16g`, `8c32g`, `16c64g`, container
CPU/RAM/swap/PID/FD ceilings, gateway budgets và PostgreSQL/ClickHouse tuning.
Nguồn sizing: [vps_profiles.py](../../backend/runtime/vps_profiles.py).
Hướng dẫn chọn/đổi profile: [VPS README](../../deploy/vps/README.md#resource-profiles-vps).

## Môi trường và image fixture

- Checkout `6cae4c1` + working tree; Python 3.9/macOS arm64, Docker Engine Linux
  aarch64, 18 CPU và 8.317.267.968 bytes RAM của VM. VM không mô phỏng toàn bộ RAM
  của các VPS lớn; chỉ chạy smoke có tải nhẹ cho profile nhỏ nhất.
- Image fixture `openwaf-vps-tiers:local-check`, ID
  `sha256:e0c1b723437dbff9141abbee681900f96da88757935e6bd8f6b0961d5d04f110`,
  Linux amd64 qua emulation. Dựng offline, không pull/push, từ image có sẵn
  `ecr.swissy.shop/c/openwaf-gateway@sha256:21c51976830d2941b75d03967c2e338f9032624cf742c1d6d222b4061a89e5a1`
  và chép runtime init/profile/default budgets hiện tại. Rust binary là binary
  trong image gốc, không phải full release build của working tree OPS-3/4.
- PostgreSQL image `ecr.swissy.shop/c/pgaio:18.6.0`; ClickHouse
  `clickhouse/clickhouse-server:25.8.33.6`; CrowdSec digest theo Compose.
- Smoke tạo project/network/volumes riêng và dọn sau khi chạy. Không gọi
  Cloudflare/ACME public hoặc thay deployment/credentials đang có.

## Lệnh và kết quả

Chạy từ repository root:

```sh
python3 -m unittest discover -s backend/runtime/tests -v
python3 deploy/vps/generate-profiles.py --check
python3 deploy/vps/tests/resource-profiles.py
python3 deploy/vps/tests/resource-profiles.py --image openwaf-vps-tiers:local-check
OPENWAF_TEST_IMAGE=openwaf-vps-tiers:local-check OPENWAF_VPS_PROFILE=2c4g python3 deploy/vps/tests/dependencies-smoke.py
OPENWAF_TEST_IMAGE=openwaf-vps-tiers:local-check OPENWAF_VPS_PROFILE=2c4g python3 deploy/vps/tests/startup-smoke.py --external-network
```

- **39 init tests đạt**: chọn profile/fingerprint trước khi tạo keys, nâng/hạ
  profile giữ credentials và bản ngay trước lần đổi gần nhất, custom config không
  bị ghi đè; validator timeout/failure, lỗi publish và symlink guards.
- **Cả năm Compose renders và native validators đạt**, trên binary macOS debug
  và image Linux. Kiểm tra cross-artifact fingerprint/commands, mọi container có
  memory/swap/CPU/PID/FD caps, gateway accounting không vượt 80% container cap, tổng CPU
  steady không vượt host, unknown profile thất bại. RAM còn sau tổng ceiling:

  | Profile | RAM còn cho host (MiB) |
  | --- | --- |
  | `2c4g` | 544 |
  | `4c8g` | 1.856 |
  | `8c16g` | 4.608 |
  | `8c32g` | 6.528 |
  | `16c64g` | 14.336 |

- **Dependency smoke `2c4g` đạt**: real Compose init/cscli/sealing, ClickHouse và
  LAPI healthy, Docker/host collector qua Unix socket private, loopback-only
  listeners, restart giữ ClickHouse data/CrowdSec decisions/key. Docker inspect
  xác nhận caps thực được áp dụng và không OOM kill; query kiểm tra
  `max_memory_usage=100663296`, `max_threads=1`. Thiếu bouncer key đã lưu bị từ chối,
  không tạo key thay thế.
- **Gateway/PG smoke `2c4g` đạt**: gateway dùng real Compose limits, PG chạy trong
  512 MiB/0,4 CPU/PID 192. SQL kiểm tra settings thực lúc tạo mới và sau restart:
  shared buffers 64 MiB, work memory 2 MiB, maintenance 32 MiB, max connections 40,
  max parallel workers 1. Private CA HTTPS, UI/login/CSRF/SSE và upstream probe
  hoạt động; gateway/PG restart giữ account/config/master keys. External network
  không bị tạo ngầm/xóa; SIGTERM dọn bootstrap locks.

## Giới hạn bằng chứng

Đây là sizing khởi điểm và functional smoke, **không phải benchmark capacity**.
Chưa kiểm tra sustained traffic, mọi policy/shadow pool cùng tải, database lớn,
ClickHouse merge/query nặng, ACME issuance dưới CPU quota nhỏ, full-stack migration
từ deployment production hoặc các profile lớn dưới tải. Accounting không giới hạn
allocator native; cần đo RSS/OOM/queue/drop/latency thực tế. Chưa build/publish full
release mới hoặc triển khai VPS thật. Rust/frontend checks không chạy lại cho thay
đổi sizing Python/Compose này; bằng chứng OPS-3/4 được lưu riêng.
