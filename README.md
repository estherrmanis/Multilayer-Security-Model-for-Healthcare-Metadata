# Multilayer-Security-Model-for-Healthcare-Metadata

Aplikasi GUI untuk **keamanan metadata rekam medis** dengan kombinasi:
- **AES-128 (CBC)** untuk enkripsi data
- **LSB steganography** untuk menyembunyikan ciphertext ke dalam gambar
- **Deteksi anomali SVM** untuk klasifikasi percobaan serangan
- Evaluasi kualitas stego-image menggunakan **MSE, PSNR, SSIM, NCC**

## Fitur Utama

1. Upload file rekam medis (TXT/PDF/DCM/DICOM) dan pilih **cover image**.
2. Enkripsi data dengan **AES-128-CBC** lalu embed menggunakan **LSB**.
3. Menampilkan informasi enkripsi (key/IV), output stego image, serta metrik evaluasi.
4. Halaman deteksi anomali menggunakan model **SVM** berbasis dataset `dataset_svm.csv`.

## Struktur File Penting

- `gui_app.py` : Aplikasi GUI (Tkinter)
- `aes_lsb.py` : Implementasi AES + LSB embedding/extraction
- `svm_security.py` : Model/logic deteksi anomali menggunakan SVM
- `train_svm_anomaly.py` : Script training model (opsional untuk eksperimen)
- `evaluation.py` : Perhitungan metrik kualitas (MSE/PSNR/SSIM/NCC)
- `dataset_svm.csv` : Dataset untuk SVM

## Prasyarat

- Python 3.9+ (disarankan)
- Library utama:
  - `opencv-python`
  - `numpy`
  - `pycryptodome`
  - `pandas`
  - `scikit-learn`
  - `scikit-image`
  - `Pillow` (untuk ikon/preview di GUI)
  - `tkinter` (biasanya sudah tersedia di Python Windows)

## Instalasi Dependency

Buat virtual environment (opsional), lalu:

```bash
pip install opencv-python numpy pycryptodome pandas scikit-learn scikit-image pillow
```

## Menjalankan Aplikasi

```bash
python gui_app.py
```

## Catatan Penting

- Cover image size dibatasi (sesuai aplikasi): maksimal **100 MB**.
- Total file medis dibatasi: maksimal **500 MB**.
- Password/Passphrase default di kode adalah `secretkey` (bisa Anda ubah di `gui_app.py` bila perlu).

## Output

- File stego hasil embedding disimpan dalam mode output sesuai `aes_lsb.py`.
- Di halaman GUI, output termasuk:
  - Metode/Mode AES
  - Key (hex) dan IV (hex)
  - Metrik kualitas citra (PSNR/MSE/SSIM/NCC)
