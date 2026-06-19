import cv2
import numpy as np
import math
from skimage.metrics import structural_similarity as ssim


def calculate_mse(image1, image2):
    image1 = image1.astype(np.float64)
    image2 = image2.astype(np.float64)
    error = image1 - image2
    mse = float(np.mean(np.square(error)))
    return mse


def calculate_psnr(mse):
    if mse == 0:
        return float("inf")
    max_pixel = 255.0
    psnr = 10 * math.log10((max_pixel ** 2) / mse)
    return psnr


def calculate_ssim(image1, image2):
    gray1 = cv2.cvtColor(image1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(image2, cv2.COLOR_BGR2GRAY)

    ssim_value, _ = ssim(gray1, gray2, full=True)
    return float(ssim_value)


def calculate_ncc(image1, image2):
    image1 = image1.astype(np.float64)
    image2 = image2.astype(np.float64)

    numerator = np.sum(image1 * image2)
    denominator = np.sqrt(np.sum(image1**2) * np.sum(image2**2))

    if denominator == 0:
        return 0

    ncc = numerator / denominator
    return float(ncc)


def evaluate_images(original_path, stego_path):
    original = cv2.imread(original_path)
    stego = cv2.imread(stego_path)

    if original is None or stego is None:
        raise ValueError("Gambar tidak ditemukan")

    if original.shape != stego.shape:
        raise ValueError("Ukuran gambar tidak sama")

    mse = calculate_mse(original, stego)
    psnr = calculate_psnr(mse)
    ssim_val = calculate_ssim(original, stego)
    ncc = calculate_ncc(original, stego)

    return {
        "MSE": mse,
        "PSNR": psnr,
        "SSIM": ssim_val,
        "NCC": ncc,
    }