import "pdf"

rule malicious_pdf_upload {
  strings:
    $malicious_keywords = "exploit" nocase
                     "malware" nocase
                     "virus" nocase
                     "trojan" nocase
                     "ransomware" nocase
                     "backdoor" nocase
  condition:
    any of them
}

rule malicious_pdf_upload {
  condition:
    pdf.contains_javascript
}

rule malicious_pdf_upload {
  condition:
    pdf.contains_executable
}

rule malicious_pdf_upload {
  condition:
    (pdf.file_size > 1000000)
}

rule malicious_pdf_upload {
  condition:
    pdf.malicious_keyword or
    pdf.contains_javascript or
    pdf.contains_executable or
    (pdf.file_size > 1000000)
}
