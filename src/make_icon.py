# -*- coding: utf-8 -*-
"""生成应用图标 assets/app.ico：深蓝渐变底 + 白色月牙 + 红色禁止斜杠"""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.abspath(os.path.join(HERE, "..", "assets"))
os.makedirs(OUT_DIR, exist_ok=True)

S = 512
M = 14

# 垂直渐变底
grad = Image.new("RGBA", (S, S), (0, 0, 0, 255))
gd = ImageDraw.Draw(grad)
top = (44, 98, 222)
bot = (18, 30, 58)
for y in range(S):
    t = y / float(S - 1)
    c = tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3))
    gd.line([(0, y), (S, y)], fill=c + (255,))

mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([M, M, S - M, S - M], radius=112, fill=255)
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
img.paste(grad, (0, 0), mask)

# 月牙
cx, cy, r = 244, 238, 138
moon = Image.new("RGBA", (S, S), (0, 0, 0, 0))
md = ImageDraw.Draw(moon)
md.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 255))
md.ellipse([cx - r + 80, cy - r - 52, cx + r + 80, cy + r - 52], fill=(0, 0, 0, 0))
img = Image.alpha_composite(img, moon)
d = ImageDraw.Draw(img)

# 禁止斜杠
band = Image.new("RGBA", (S, S), (0, 0, 0, 0))
bd = ImageDraw.Draw(band)
bd.line([(158, 392), (390, 160)], fill=(228, 58, 58, 255), width=50)
img = Image.alpha_composite(img, band)
d = ImageDraw.Draw(img)

# 星点
for (sx, sy, sr, a) in ((392, 356, 10, 235), (344, 414, 6, 190)):
    d.ellipse([sx - sr, sy - sr, sx + sr, sy + sr], fill=(255, 255, 255, a))

# 把圆角外的部分清掉（斜杠/星星可能越界）
final = Image.new("RGBA", (S, S), (0, 0, 0, 0))
final.paste(img, (0, 0), mask)

sizes = [256, 128, 64, 48, 32, 16]
final.save(os.path.join(OUT_DIR, "app.png"))
final.save(os.path.join(OUT_DIR, "app.ico"), format="ICO", sizes=[(s, s) for s in sizes])
print("icon ->", os.path.join(OUT_DIR, "app.ico"))
