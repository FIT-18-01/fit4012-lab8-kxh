# Lab 8 - Peer review response

## Nhóm được review

- Tên nhóm: KXH
- Người review: Nhóm KxH 

## Góp ý nhận được

1. README còn thiếu thông tin thành viên và phân công công việc.
2. Cần bổ sung log minh chứng quá trình chạy Sender/Receiver.
3. Cần kiểm tra rõ hơn các trường hợp dữ liệu bị thay đổi như sai hash hoặc ciphertext bị can thiệp.

## Phản hồi và chỉnh sửa

| Góp ý | Phản hồi của nhóm | File/commit đã sửa |
|---|---|---|
| README còn thiếu thông tin thành viên và phân công công việc. | Nhóm đã cập nhật đầy đủ họ tên, MSSV, vai trò demo và phân công nhiệm vụ của từng thành viên. | `README.md` |
| Cần bổ sung log minh chứng quá trình chạy Sender/Receiver. | Nhóm đã chạy demo Sender/Receiver và lưu log minh chứng vào thư mục `logs/`. | `logs/` |
| Cần kiểm tra rõ hơn các trường hợp dữ liệu bị thay đổi như sai hash hoặc ciphertext bị can thiệp. | Nhóm đã bổ sung/kiểm tra các test liên quan đến packet, hash bị sửa đổi và ciphertext bị can thiệp. | `tests/` |

## Tự đánh giá sau chỉnh sửa

- Chương trình chạy được demo Sender/Receiver: YES
- Có kiểm tra SHA-256: YES
- Có mã hóa DES key bằng RSA-OAEP: YES
- Có test cho packet/tamper: YES
- Có log minh chứng: YES