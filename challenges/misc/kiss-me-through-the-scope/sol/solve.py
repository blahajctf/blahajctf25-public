from PIL import Image, ImageDraw, ImageFont

OCR_OFFSETS = [(24, 35), (19, 21), (23, 16)]
OCR_MAPPING = {(False, False, False): [6], (False, False, True): [2], (False, True, False): [1], (False, True, True): [7], (True, False, False): [5], (True, False, True): [4, 9], (True, True, False): [0], (True, True, True): [3, 8]}
DIGITS = [(77, 32), (161, 32), (245, 32), (329, 32)]

def identify_digit_from_pixels(pixel_data):
    signature = tuple(pixel_data)
    return OCR_MAPPING.get(signature, None) 

i = Image.open("tmp.png")

for n in range(4):
    res = []
    for j in range(3):
        res.append(i.getpixel((DIGITS[n][0]+OCR_OFFSETS[j][0], DIGITS[n][1]+OCR_OFFSETS[j][1]))[0] < 128)
    print(identify_digit_from_pixels(res))