import piexif
from PIL import Image


class OmegaTools:
    @staticmethod
    def strip_metadata(image_path: str):
        """Removes GPS and Camera data from images."""
        try:
            img = Image.open(image_path)
            data = list(img.getdata())
            img_no_exif = Image.new(img.mode, img.size)
            img_no_exif.putdata(data)

            # Overwrite original
            img_no_exif.save(image_path)
            return True, "Metadata stripped cleanly."
        except Exception as e:
            return False, str(e)
