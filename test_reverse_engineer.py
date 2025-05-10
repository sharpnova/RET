import pytest
from reverse_engineer import ReverseEngineer

def test_file_type_detection(tmp_path):
    file = tmp_path / "test.exe"
    file.write_bytes(b'MZ\x00\x00')
    re = ReverseEngineer(file)
    assert re._detect_file_type() == 'PE'

def test_metadata_extraction(tmp_path):
    file = tmp_path / "test.exe"
    file.write_bytes(b'MZ\x00\x00')
    re = ReverseEngineer(file)
    re.extract_metadata()
    assert 'Machine' in re.metadata

def test_obfuscation_detection(tmp_path):
    file = tmp_path / "test.bin"
    file.write_bytes(b'\x00' * 1024)
    re = ReverseEngineer(file)
    re.detect_obfuscation()
    assert not re.obfuscation_detected