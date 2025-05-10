import dis
import logging

logger = logging.getLogger(__name__)

def supports(file_type):
    return file_type == 'Python'

def analyze(file_path):
    try:
        with open(file_path, 'rb') as f:
            code = f.read()
        instructions = list(dis.get_instructions(code))
        return {'instructions': [str(i) for i in instructions]}
    except Exception as e:
        logger.error("Python plugin failed", error=str(e))
        return {'error': str(e)}