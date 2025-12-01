from PIL import Image
import tempfile, subprocess
img= Image.open("/home/m/Desktop/Distributed-P2P-Cloud/dog_1.png")

with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
    img.save(tmp.name)  # Save image to temp file
    subprocess.Popen(["/usr/bin/eog", tmp.name], env={})  # empty env avoids Snap

