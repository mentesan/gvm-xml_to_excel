# gvm-xml_to_excel

# Features
- Generate excel file ".xlsx" file from a XML GVM report
- Prints headers in Brazilian Portuguese

# Usage
You'll need to install
"github.com/360EntSecGroup-Skylar/excelize"

# How to compile:
```
  go mod init gvm-xml_to_excel.go
  go build -ldflags="-s -w" gvm-xml_to_excel.go
  upx --brute gvm-xml_to_excel # optional
```


```
gvm-xml_to_excel input.xml output.xlsx
```



