import base64
import json
from pathlib import Path

from aes_lsb import process_secure_embedding
from evaluation import evaluate_images
from svm_security import SVMAnomalyDetector


def ask_login(detector: SVMAnomalyDetector, max_attempts: int = 3) -> bool:
    valid_username = "admin"
    valid_password = "simbakucingaku"
    attempts = max_attempts

    print("=== LOGIN SISTEM KEAMANAN REKAM MEDIS ===")
    while attempts > 0:
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        # Kredensial benar dianggap aman dan tidak dinilai sebagai serangan.
        if username == valid_username and password == valid_password:
            print("[OK] Login berhasil.\n")
            return True

        pred = detector.predict_login(username, password)
        if pred.is_anomaly:
            attempts -= 1
            print(
                f"[ANOMALI] Serangan terdeteksi: {pred.detected_attack} | "
                f"confidence={pred.confidence:.2f} | sisa={attempts}"
            )
            continue

        attempts -= 1
        print(f"[GAGAL] Kredensial salah. Sisa kesempatan: {attempts}")

    print("\n[SISTEM TERKUNCI] Input login dinonaktifkan.")
    return False


def run_secure_pipeline() -> None:
    print("=== INPUT DATA ===")
    medical_file = Path(input("Path file rekam medis (dcm/pdf/txt): ").strip())
    cover_image = Path(input("Path gambar cover (png/jpg/bmp): ").strip())
    passphrase = input("Passphrase AES-128-CBC [default: secretkey]: ").strip() or "secretkey"

    if not medical_file.exists():
        raise FileNotFoundError(f"File medis tidak ditemukan: {medical_file}")
    if not cover_image.exists():
        raise FileNotFoundError(f"Gambar cover tidak ditemukan: {cover_image}")

    raw_bytes = medical_file.read_bytes()
    payload = {
        "filename": medical_file.name,
        "content_b64": base64.b64encode(raw_bytes).decode("utf-8"),
    }
    message = json.dumps(payload)
    output_path = f"cipher_{cover_image.stem}.png"

    print("\n=== PROSES AES-LSB ===")
    enc_info = process_secure_embedding(
        message=message,
        image_path=str(cover_image),
        passphrase=passphrase,
        output_path=output_path,
    )
    metrics = evaluate_images(str(cover_image), enc_info["stego_path"])

    print("\n=== HASIL ===")
    print(f"Gambar hasil   : {enc_info['stego_path']}")
    print(f"Algoritma      : {enc_info['algorithm']}")
    print(f"Mode           : {enc_info['mode']}")
    print(f"Key (Hex)      : {enc_info['key_hex']}")
    print(f"IV (Hex)       : {enc_info['iv_hex']}")

    print("\n=== EVALUASI ===")
    print(f"PSNR           : {metrics['PSNR']:.2f} dB")
    print(f"MSE            : {metrics['MSE']:.6f}")
    print(f"SSIM           : {metrics['SSIM']:.6f}")
    print(f"NCC            : {metrics['NCC']:.6f}")


def main() -> None:
    detector = SVMAnomalyDetector("dataset_svm.csv")
    if not ask_login(detector, max_attempts=3):
        return
    run_secure_pipeline()


if __name__ == "__main__":
    main()
