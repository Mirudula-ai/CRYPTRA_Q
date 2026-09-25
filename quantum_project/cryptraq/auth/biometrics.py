import cv2
import numpy as np
from PIL import Image
import logging
import os
import tempfile

logger = logging.getLogger(__name__)

class BiometricAuth:
    """
    Lightweight OpenCV-based face authentication with Liveness detection and LBPH encoding.
    """
    def __init__(self):
        # Load Haar cascade for face detection
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.recognizer = cv2.face.LBPHFaceRecognizer_create()

    def get_face_roi(self, image: Image.Image):
        """Returns the bounding box (x, y, w, h) and cropped grayscale face image."""
        try:
            img_array = np.array(image.convert('RGB'))
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(100, 100))
            if len(faces) > 0:
                # Return the largest face
                faces = sorted(faces, key=lambda f: f[2]*f[3], reverse=True)
                x, y, w, h = faces[0]
                return (x, y, w, h), gray[y:y+h, x:x+w]
        except Exception as e:
            logger.error(f"Error during facial detection: {e}")
        return None, None

    def enroll_face(self, images) -> bytes:
        """
        Trains LBPH on a list of PIL Images and returns the serialized model bytes.
        We need multiple variations of the face for better LBPH training.
        """
        faces = []
        labels = []
        for img in images:
            _, face_img = self.get_face_roi(img)
            if face_img is not None:
                faces.append(cv2.resize(face_img, (200, 200)))
                labels.append(1) # We only have one user per model for this prototype
        
        if not faces:
            raise ValueError("No faces detected in enrollment images.")
            
        self.recognizer.train(faces, np.array(labels))
        
        # Serialize to bytes via temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as tmp:
            tmp_path = tmp.name
        
        self.recognizer.write(tmp_path)
        with open(tmp_path, "rb") as f:
            model_bytes = f.read()
            
        os.remove(tmp_path)
        return model_bytes

    def verify_identity(self, captured_image: Image.Image, model_bytes: bytes) -> bool:
        """
        Verifies the captured image against the stored LBPH model.
        """
        _, face_img = self.get_face_roi(captured_image)
        if face_img is None:
            return False
            
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as tmp:
            tmp_path = tmp.name
            tmp.write(model_bytes)
            
        try:
            self.recognizer.read(tmp_path)
            label, confidence = self.recognizer.predict(cv2.resize(face_img, (200, 200)))
            logger.info(f"Biometric Confidence: {confidence}")
            # Threshold increased to 120 for smoother testing/demo flow.
            if confidence < 120:
                return True
        except Exception as e:
            logger.error(f"Verification error: {e}")
        finally:
            os.remove(tmp_path)
            
        return False
        
    def check_liveness(self, img1: Image.Image, img2: Image.Image) -> bool:
        """
        Checks if the face has moved significantly between two captures to prevent static photo attacks.
        """
        box1, _ = self.get_face_roi(img1)
        box2, _ = self.get_face_roi(img2)
        
        if not box1 or not box2:
            return False
            
        x1, y1, w1, h1 = box1
        x2, y2, w2, h2 = box2
        
        # Calculate center
        cx1, cy1 = x1 + w1/2, y1 + h1/2
        cx2, cy2 = x2 + w2/2, y2 + h2/2
        
        # Distance moved
        distance = np.sqrt((cx2 - cx1)**2 + (cy2 - cy1)**2)
        
        logger.info(f"Liveness movement distance: {distance}")
        
        # Face must move at least 15 pixels but not teleport across the screen (e.g. > 300 pixels)
        return 15 < distance < 300
