import pytest
from src.analysis.content_analyzer import ContentAnalyzer

def test_content_analyzer_regex():
    analyzer = ContentAnalyzer()
    metadata = {"name": "test.txt", "share": "docs"}
    content = b"My AWS Key is AKIA1234567890ABCDEF and secret is 'abc/def+ghi/jkl+mno/pqr+stu/vwx+yz0123456'"
    
    findings = analyzer.analyze(content, metadata)
    
    types = [f["type"] for f in findings]
    assert "aws_key" in types
    assert "aws_secret" in types

def test_content_analyzer_no_match():
    analyzer = ContentAnalyzer()
    metadata = {"name": "clean.txt", "share": "docs"}
    content = b"Just a normal file without secrets."
    
    findings = analyzer.analyze(content, metadata)
    assert len(findings) == 0
