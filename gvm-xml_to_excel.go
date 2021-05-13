package main

import (
	"encoding/xml"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	//	"strconv"
	"strings"
)

var f = excelize.NewFile()

type ReportFile struct {
	XMLName      xml.Name `xml:"report"`
	Owner        Owner    `xml:"owner"`
	Name         string   `xml:"name"`
	Comment      string   `xml:"comment"`
	Creation     string   `xml:"creation_time"`
	Modification string   `xml:"modification_time"`
	Writable     string   `xml:"writable"`
	In_Use       string   `xml:"in_use"`
	Format       Format
	Report       Report
}

type Owner struct {
	XMLName xml.Name `xml:"owner"`
	Name    string   `xml:"name"`
}

type Format struct {
	XMLName xml.Name `xml:"report_format"`
	Name    string   `xml:"name"`
}

type Report struct {
	XMLName    xml.Name   `xml:"report"`
	id         string     `xml:"id,attr"`
	Closed_CVE Closed_CVE `xml:"closed_cves"`
	Vulns      Vulns      `xml:"vulns"`
	OS         OS         `xml:"os"`
	Apps       Apps       `xml:"apps"`
	SSL        SSL        `xml:"ssl_certs"`
	Task       Task       `xml:"task"`
	ScanStart  string     `xml:"scan_start"`
	Timezone   string     `xml:"timezone"`
	Ports      Ports
	Results    Results
	Severity   Severity
	Errors     Errors
}

type Closed_CVE struct {
	XMLName xml.Name `xml:"closed_cves"`
	Count   string   `xml:"count"`
}

type Vulns struct {
	XMLName xml.Name `xml:"vulns"`
	Count   string   `xml:"count"`
}

type OS struct {
	XMLName xml.Name `xml:"os"`
	Count   string   `xml:"count"`
}

type Apps struct {
	XMLName xml.Name `xml:"apps"`
	Count   string   `xml:"count"`
}

type SSL struct {
	XMLName xml.Name `xml:"ssl_certs"`
	Count   string   `xml:"count"`
}

type Task struct {
	XMLName xml.Name `xml:"task"`
	id      string   `xml:"id,attr"`
	Comment string   `xml:"comment"`
	Name    string   `xml:"name"`
}

type Ports struct {
	XMLName xml.Name `xml:"ports"`
	max     string   `xml:"max,attr"`
	start   string   `xml:"start,attr"`
	Port    []Port   `xml:"port"`
}

// A Slice
type Port struct {
	XMLName  xml.Name `xml:"port"`
	Name     string   `xml:"port"`
	Host     string   `xml:"host"`
	Severity string   `xml:"severity"`
	Threat   string   `xml:"threat"`
}

type Results struct {
	XMLName xml.Name `xml:"results"`
	Result  []Result `xml:"result"`
}

type Result struct {
	XMLName   xml.Name  `xml:"result"`
	id        string    `xml:"id,attr"`
	Name      string    `xml:"name"`
	Comment   string    `xml:"comment"`
	Detection Detection `xml:"detection"`
	//Host        Host
	Host        string `xml:"host"`
	Port        string `xml:"port"`
	NVT         NVT    `xml:"nvt"`
	Threat      string `xml:"threat"`
	Severity    string `xml:"severity"`
	QOD         QOD
	Description string `xml:"description"`
}

/* Canceled, getting via string directly
type Host struct {
	XMLName  xml.Name `xml:"host"`
	Hostname string   `xml:"hostname"`
}
*/

type NVT struct {
	XMLName   xml.Name `xml:"nvt"`
	oid       string   `xml:"oid,attr"`
	Type      string   `xml:"type"`
	Name      string   `xml:"name"`
	Family    string   `xml:"family"`
	CVSS_Base string   `xml:"cvss_base"`
	Tags      string   `xml:"tags"`
	Solution  string   `xml:"solution"`
	Refs      Refs     `xml:"refs"`
}

type Refs struct {
	InnerXML string `xml:",innerxml"`
}

type QOD struct {
	XMLName xml.Name `xml:"qod"`
	Value   string   `xml:"value"`
	Type    string   `xml:"type"`
}

type Severity struct {
	XMLName  xml.Name `xml:"severity"`
	Full     string   `xml:"full"`
	Filtered string   `xml:"filtered"`
}

type Detection struct {
	XMLName xml.Name `xml:"detection"`
	Result  Detection_Result
}

type Detection_Result struct {
	XMLName xml.Name `xml:"result"`
	id      string   `xml:"id,attr"`
	Details Detection_Details
}

type Detection_Details struct {
	XMLName xml.Name           `xml:"details"`
	Detail  []Detection_Detail `xml:"detail"`
}

type Detection_Detail struct {
	XMLName xml.Name `xml:"detail"`
	Name    string   `xml:"name"`
	Value   string   `xml:"value"`
}

type Errors struct {
	XMLName xml.Name `xml:"errors"`
	Count   string   `xml:"count"`
	Error   []Error  `xml:"error"`
}

type Error struct {
	XMLName xml.Name `xml:"error"`
	Host    string   `xml:"host"`
	Port    string   `xml:"port"`
	NVT     NVT      `xml:"nvt"`
}

// Order errors by CVSS
type ByCVSS []Error

func (a ByCVSS) Len() int { return len(a) }
func (a ByCVSS) Less(i, j int) bool {
	//b, _ := strconv.Atoi(a[i].NVT.CVSS_Base)
	//c, _ := strconv.Atoi(a[j].NVT.CVSS_Base)
	return a[i].NVT.CVSS_Base > a[j].NVT.CVSS_Base
}
func (a ByCVSS) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func loadFromXML(filename string, key interface{}) error {
	in, err := os.Open(filename)
	if err != nil {
		return err
	}

	decodeXML := xml.NewDecoder(in)
	err = decodeXML.Decode(key)
	if err != nil {
		return err
	}
	in.Close()
	return nil
}

func PrintHeader(f *excelize.File, sheet string, reportFile ReportFile) {
	f.SetColWidth(sheet, "A", "A", 20)
	f.SetColWidth(sheet, "B", "B", 30)

	// Right align colum A
	style, err := f.NewStyle(`{"alignment":{"horizontal":"right","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"","wrap_text":true}}`)
	if err != nil {
		fmt.Println(err)
	}
	err = f.SetCellStyle(sheet, "A1", "A13", style)
	// Centralize column B
	style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"","wrap_text":true}}`)
	if err != nil {
		fmt.Println(err)
	}
	err = f.SetCellStyle(sheet, "B1", "B13", style)

	// Print Headers
	cell_headers := map[string]string{"A1": "Relatório", "A2": "Proprietário", "A3": "Data", "A4": "Data de Alteração", "A5": "Início", "A6": "Timezone", "A7": "Tarefa", "A8": "Comentários", "A9": "CVEs", "A10": "Vulnerabilidades", "A11": "Aplicações", "A12": "Certificados SSL", "A13": "Total de portas"}
	for k, v := range cell_headers {
		f.SetCellValue(sheet, k, v)
	}

	// Print cells
	cell_values := map[string]string{"B1": reportFile.Name, "B2": reportFile.Owner.Name, "B3": reportFile.Creation, "B4": reportFile.Modification, "B5": reportFile.Report.ScanStart, "B6": reportFile.Report.Timezone, "B7": reportFile.Report.Task.Name, "B8": reportFile.Report.Task.Comment, "B9": reportFile.Report.Closed_CVE.Count, "B10": reportFile.Report.Vulns.Count, "B11": reportFile.Report.Apps.Count, "B12": reportFile.Report.SSL.Count}
	for k, v := range cell_values {
		f.SetCellValue(sheet, k, v)
	}
	// Ports - Because its integer
	ports := reportFile.Report.Ports.Port
	f.SetCellValue(sheet, "B13", len(ports))
}

func PrintHeaderChart(f *excelize.File, sheet string, results []Result) {
	var results_high, results_medium, results_low, results_alarm, results_log, results_debug []Result

	for i := 0; i < len(results); i++ {
		if results[i].Threat == "High" {
			results_high = append(results_high, results[i])
		} else if results[i].Threat == "Medium" {
			results_medium = append(results_medium, results[i])
		} else if results[i].Threat == "Low" {
			results_low = append(results_low, results[i])
		} else if results[i].Threat == "Alarm" {
			results_alarm = append(results_alarm, results[i])
		} else if results[i].Threat == "Log" {
			results_log = append(results_log, results[i])
		} else if results[i].Threat == "Debug" {
			results_debug = append(results_debug, results[i])
		}
	}
	// Print Headers
	headers := map[string]string{"C1": "Crítico", "D1": "Médio", "E1": "Baixo", "F1": "Alarm", "G1": "Log", "H1": "Debug"}
	for k, v := range headers {
		f.SetCellValue(sheet, k, v)
	}

	high := len(results_high)
	medium := len(results_medium)
	low := len(results_low)
	alarm := len(results_alarm)
	log := len(results_log)
	debug := len(results_debug)

	// Print cell values
	cell_values := map[string]int{"C2": high, "D2": medium, "E2": low, "F2": alarm, "G2": log, "H2": debug}
	for k, v := range cell_values {
		f.SetCellValue(sheet, k, v)
	}

	if err := f.AddChart("Geral", "C3", `{
        "type": "pie3D",
        "series": [
        {
            "name": "Geral!$C$1",
            "categories": "Geral!$C$1:$H$1",
            "values": "Geral!$C$2:$H$2"
        }],
        "title":
        {
            "name": "Falhas detectadas"
        },
        "plotarea":
        {
            "show_bubble_size": false,
            "show_cat_name": false,
            "show_leader_lines": false,
            "show_percent": true,
            "show_series_name": false,
            "show_val": true
        }

    }`); err != nil {
		fmt.Println(err)
		fmt.Println("Erro gerando gráfico")
		return
	}
}

func SetStyle(level string) (err error, header_style, cell_style int) {
	if level == "Crítico" || level == "Possíveis falhas" {
		// Style for results Header
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#D60D14"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"D60D14","style":1},{"type":"top","color":"D60D14","style":1},{"type":"bottom","color":"D60D14","style":1},{"type":"right","color":"D60D14","style":1}]}`)
	} else if level == "Médio" {
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#CC6104"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"CC6104","style":1},{"type":"top","color":"CC6104","style":1},{"type":"bottom","color":"CC6104","style":1},{"type":"right","color":"CC6104","style":1}]}`)
	} else if level == "Baixo" {
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#1f44FF"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"1f44FF","style":1},{"type":"top","color":"1f44FF","style":1},{"type":"bottom","color":"1f44FF","style":1},{"type":"right","color":"1f44FF","style":1}]}`)

	} else if level == "Alarm" {
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#560982"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"560982","style":1},{"type":"top","color":"560982","style":1},{"type":"bottom","color":"560982","style":1},{"type":"right","color":"560982","style":1}]}`)
	} else if level == "Log" {
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#046E29"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"046E29","style":1},{"type":"top","color":"046E29","style":1},{"type":"bottom","color":"046E29","style":1},{"type":"right","color":"046E29","style":1}]}`)
	} else if level == "Debug" {
		header_style, err = f.NewStyle(`{"alignment":{"horizontal":"center","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":true,"text_rotation":0,"vertical":"center","wrap_text":true}, "fill":{"type":"pattern","color":["#08CAD1"],"pattern":1}}`)

		cell_style, err = f.NewStyle(`{"alignment":{"horizontal":"left","ident":1,"justify_last_line":true,"reading_order":0,"relative_indent":1,"shrink_to_fit":false,"text_rotation":0,"vertical":"center","wrap_text":true}, "border":[{"type":"left","color":"08CAD1","style":1},{"type":"top","color":"08CAD1","style":1},{"type":"bottom","color":"08CAD1","style":1},{"type":"right","color":"08CAD1","style":1}]}`)
	}
	if err != nil {
		fmt.Println("Erro no Style")
		fmt.Println(err)
	}

	return err, header_style, cell_style
}

func PrintResults(f *excelize.File, sheet string, results []Result) {
	var err error
	// Define Style color for results data
	err, header_style, cell_style := SetStyle(sheet)
	if err != nil {
		fmt.Println("Error setting Style")
		fmt.Println(err)
	}

	cells := []string{"A1", "B1", "C1", "D1", "E1", "F1", "G1", "H1", "I1", "J1", "K1", "L1"}
	for i := 0; i < len(cells); i++ {
		err = f.SetCellStyle(sheet, cells[i], cells[i], header_style)
	}
	if err != nil {
		fmt.Println("Erro no Primeiro")
		fmt.Println(err)
	}

	f.SetColWidth(sheet, "A", "A", 10)
	f.SetColWidth(sheet, "B", "B", 30)
	f.SetColWidth(sheet, "C", "C", 15)
	f.SetColWidth(sheet, "D", "D", 15)
	f.SetColWidth(sheet, "E", "E", 10)
	f.SetColWidth(sheet, "F", "F", 15)
	f.SetColWidth(sheet, "G", "G", 45)
	f.SetColWidth(sheet, "H", "J", 100)
	f.SetColWidth(sheet, "K", "L", 40)

	cell_values := map[string]string{"A1": "Ameaça", "B1": "Nome", "C1": "Host", "D1": "Port", "E1": "CVSS", "F1": "Família", "G1": "Falha", "H1": "Descrição", "I1": "Solução", "J1": "Referências", "K1": "Sistema", "L1": "NVT"}
	for k, v := range cell_values {
		f.SetCellValue(sheet, k, v)
	}

	if err != nil {
		fmt.Println("ERRO no style-2")
		fmt.Println(err)
	}

	for i := 0; i < len(results); i++ {
		num := i + 2
		A := fmt.Sprintf("A%d", num)
		B := fmt.Sprintf("B%d", num)
		C := fmt.Sprintf("C%d", num)
		D := fmt.Sprintf("D%d", num)
		E := fmt.Sprintf("E%d", num)
		F := fmt.Sprintf("F%d", num)
		G := fmt.Sprintf("G%d", num)
		H := fmt.Sprintf("H%d", num)
		I := fmt.Sprintf("I%d", num)
		J := fmt.Sprintf("J%d", num)
		K := fmt.Sprintf("K%d", num)
		L := fmt.Sprintf("L%d", num)

		var cells []string
		cells = append(cells, A)
		cells = append(cells, B)
		cells = append(cells, C)
		cells = append(cells, D)
		cells = append(cells, E)
		cells = append(cells, F)
		cells = append(cells, G)
		cells = append(cells, H)
		cells = append(cells, I)
		cells = append(cells, J)
		cells = append(cells, K)
		cells = append(cells, L)
		for i := 0; i < len(cells); i++ {
			err = f.SetCellStyle(sheet, cells[i], cells[i], cell_style)
		}
		if err != nil {
			fmt.Println("Erro no Loop")
			fmt.Println(err)
		}

		f.SetCellValue(sheet, A, results[i].Threat)
		f.SetCellValue(sheet, B, results[i].Name)
		f.SetCellValue(sheet, C, results[i].Host)
		f.SetCellValue(sheet, D, results[i].Port)

		// Detection details
		// Product and Software
		details := results[i].Detection.Result.Details.Detail
		if len(details) > 1 {
			f.SetCellValue(sheet, K, details[0].Value)
			f.SetCellValue(sheet, L, details[3].Value)
		}
		// NVTs (Network Vulnerability Test)
		nvt := results[i].NVT
		f.SetCellValue(sheet, E, nvt.CVSS_Base)
		f.SetCellValue(sheet, F, nvt.Family)
		f.SetCellValue(sheet, G, nvt.Name)
		f.SetCellValue(sheet, H, nvt.Tags)
		f.SetCellValue(sheet, I, nvt.Solution)
		// Referencias (CVE, URL, etc) must get it from "InnerXML"
		a := regexp.MustCompile(`<ref type=".*?" id="`)
		refs := a.Split(nvt.Refs.InnerXML, -1)

		var references string
		for _, ref := range refs {
			ref = strings.TrimSuffix(ref, "\"></ref>")
			references += fmt.Sprintf("%s\n", ref)
		}
		f.SetCellValue(sheet, J, references)
	}
}

func PrintErrors(f *excelize.File, sheet string, errors []Error) {
	var err error
	err, header_style, cell_style := SetStyle(sheet)

	cells := []string{"A1", "B1", "C1", "D1", "E1"}
	for i := 0; i < len(cells); i++ {
		err = f.SetCellStyle(sheet, cells[i], cells[i], header_style)
	}
	if err != nil {
		fmt.Println("Erro no Primeiro")
		fmt.Println(err)
	}

	f.SetColWidth(sheet, "A", "B", 15)
	f.SetColWidth(sheet, "C", "C", 50)
	f.SetColWidth(sheet, "D", "D", 10)
	f.SetColWidth(sheet, "E", "E", 15)

	cell_values := map[string]string{"A1": "Host", "B1": "Port", "C1": "Falha", "D1": "CVSS"}
	for k, v := range cell_values {
		f.SetCellValue(sheet, k, v)
	}

	for i := 0; i < len(errors); i++ {
		num := i + 2
		A := fmt.Sprintf("A%d", num)
		B := fmt.Sprintf("B%d", num)
		C := fmt.Sprintf("C%d", num)
		D := fmt.Sprintf("D%d", num)
		E := fmt.Sprintf("E%d", num)

		var cells []string
		cells = append(cells, A)
		cells = append(cells, B)
		cells = append(cells, C)
		cells = append(cells, D)
		cells = append(cells, E)
		for i := 0; i < len(cells); i++ {
			err = f.SetCellStyle(sheet, cells[i], cells[i], cell_style)
		}
		if err != nil {
			fmt.Println("Erro no Loop")
			fmt.Println(err)
		}

		f.SetCellValue(sheet, A, errors[i].Host)
		f.SetCellValue(sheet, B, errors[i].Port)
		f.SetCellValue(sheet, C, errors[i].NVT.Name)
		f.SetCellValue(sheet, D, errors[i].NVT.CVSS_Base)
	}

}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a filename!")
		return
	}

	filename := arguments[1]
	xmlFile, err := os.Open(filename)
	if err != nil {
		fmt.Println("Erro ao abrir arquivo", err)
	}
	defer xmlFile.Close()
	byteValue, _ := ioutil.ReadAll(xmlFile)

	var reportFile ReportFile
	xml.Unmarshal(byteValue, &reportFile)

	// Results
	results := reportFile.Report.Results.Result
	// Declare many variables at once
	var results_high, results_medium, results_low, results_alarm, results_log, results_debug []Result

	for i := 0; i < len(results); i++ {
		if results[i].Threat == "High" {
			results_high = append(results_high, results[i])
		} else if results[i].Threat == "Medium" {
			results_medium = append(results_medium, results[i])
		} else if results[i].Threat == "Low" {
			results_low = append(results_low, results[i])
		} else if results[i].Threat == "Alarm" {
			results_alarm = append(results_alarm, results[i])
		} else if results[i].Threat == "Log" {
			results_log = append(results_log, results[i])
		} else if results[i].Threat == "Debug" {
			results_debug = append(results_debug, results[i])
		}
	}

	// Print First sheet
	f.SetSheetName("Sheet1", "Geral")
	PrintHeader(f, "Geral", reportFile)
	PrintHeaderChart(f, "Geral", results)

	// Print by "Threat Level"
	if len(results_high) > 0 {
		index := f.NewSheet("Crítico")
		PrintResults(f, "Crítico", results_high)
		f.SetActiveSheet(index)
	}
	if len(results_medium) > 0 {
		index := f.NewSheet("Médio")
		PrintResults(f, "Médio", results_medium)
		f.SetActiveSheet(index)
	}
	if len(results_low) > 0 {
		index := f.NewSheet("Baixo")
		PrintResults(f, "Baixo", results_low)
		f.SetActiveSheet(index)
	}
	if len(results_alarm) > 0 {
		index := f.NewSheet("Alarm")
		PrintResults(f, "Alarm", results_alarm)
		f.SetActiveSheet(index)
	}
	if len(results_log) > 0 {
		index := f.NewSheet("Log")
		PrintResults(f, "Log", results_log)
		f.SetActiveSheet(index)
	}
	if len(results_debug) > 0 {
		index := f.NewSheet("Debug")
		PrintResults(f, "Debug", results_debug)
		f.SetActiveSheet(index)
	}

	// Errors, possible flaws
	errors := reportFile.Report.Errors.Error
	sort.Sort(ByCVSS(errors))

	if len(errors) > 0 {
		index := f.NewSheet("Possíveis falhas")
		PrintErrors(f, "Possíveis falhas", errors)
		f.SetActiveSheet(index)
	}

	f.SetActiveSheet(0)
	if err := f.SaveAs("/home/micron/winhome/Downloads/report1.xlsx"); err != nil {
		fmt.Println(err)
	}
}
