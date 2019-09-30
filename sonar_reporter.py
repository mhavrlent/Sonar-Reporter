import sys
import json
import requests
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import datetime as datetime
import time as time
import pytz
import dateutil.parser

TEMPLATE = "reportTemplate.html"

# performs API calls to obtain the sonar qube analysis results for the given component_key (project)
def generate_report(url, username, password, component_key):
    server_version = get_string(url, username, password, "/api/server/version")

    json_data = get_json(url, username, password, "/api/navigation/component?componentKey=" + component_key)
    project_name = json_data["name"]
    project_organization = json_data["organization"]
    project_quality_gate = json_data["qualityGate"]
    project_quality_profiles = json_data["qualityProfiles"]
    project_analysis_date = dateutil.parser.parse(json_data["analysisDate"])
    project_analysis_date_utc = str(datetime.datetime.utcfromtimestamp(project_analysis_date.timestamp())) + " UTC"
    project_version = json_data["version"]

    quality_gates_table = ""
    if project_quality_gate:
        quality_gates_table += "<table><tr><th>Key</th><th>Name</th><th>Is Default</th></tr>"
        if 'key' in project_quality_gate:
            quality_gates_table += "<td>" + str(project_quality_gate['key']) + "</td>"
        else:
            quality_gates_table += "<td></td>"
        if 'name' in project_quality_gate:
            quality_gates_table += "<td>" + project_quality_gate['name'] + "</td>"
        else:
            quality_gates_table += "<td></td>"
        if 'isDefault' in project_quality_gate:
            quality_gates_table += "<td>" + str(project_quality_gate['isDefault']) + "</td>"
        else:
            quality_gates_table += "<td></td>"

    quality_gates_table += "</table>"

    quality_profiles_table = ""
    if len(project_quality_profiles) > 0:
        quality_profiles_table += "<table><tr><th>Key</th><th>Name</th><th>Language</th></tr>"
        for quality_profile in project_quality_profiles:
            quality_profiles_table += "<tr>"
            if 'key' in quality_profile:
                quality_profiles_table += "<td>" + quality_profile['key'] + "</td>"
            else:
                quality_profiles_table += "<td></td>"
            if 'name' in quality_profile:
                quality_profiles_table += "<td>" + quality_profile['name'] + "</td>"
            else:
                quality_profiles_table += "<td></td>"
            if 'language' in quality_profile:
                quality_profiles_table += "<td>" + quality_profile['language'] + "</td>"
            else:
                quality_profiles_table += "<td></td>"
            quality_profiles_table += "</tr>"

    quality_profiles_table += "</table>"

    json_data = get_json(url, username, password, 
        "/api/measures/component?additionalFields=metrics%2Cperiods&componentKey=" + component_key +
        "&metricKeys=alert_status%2Cquality_gate_details%2Cbugs%2Cnew_bugs%2Creliability_rating%2Cnew_reliability_rating%2Cvulnerabilities%2Cnew_vulnerabilities%2Csecurity_rating%2Cnew_security_rating%2Ccode_smells%2Cnew_code_smells%2Csqale_rating%2Cnew_maintainability_rating%2Csqale_index%2Cnew_technical_debt%2Ccoverage%2Cnew_coverage%2Cnew_lines_to_cover%2Ctests%2Cduplicated_lines_density%2Cnew_duplicated_lines_density%2Cduplicated_blocks%2Cncloc%2Cncloc_language_distribution%2Cprojects%2Cnew_lines")
    measures = json_data['component']['measures']
    periods = json_data["periods"]
    metrics = json_data["metrics"]

    quality_gate_status = get_value_for_metric_key("alert_status", measures)
    if quality_gate_status == "ERROR":
        quality_gate_status = "Failed"
    bugs = get_value_for_metric_key("bugs", measures)
    vulnerabilities = get_value_for_metric_key("vulnerabilities", measures)
    security_rating = get_value_for_metric_key("security_rating", measures)
    code_smells = get_value_for_metric_key("code_smells", measures)
    coverage = get_value_for_metric_key("coverage", measures)
    duplicated_blocks = get_value_for_metric_key("duplicated_blocks", measures)
    duplicated_lines_density = get_value_for_metric_key("duplicated_lines_density", measures)
    ncloc = get_value_for_metric_key("ncloc", measures)
    ncloc_language_distribution = get_value_for_metric_key("ncloc_language_distribution", measures)
    reliability_rating = get_value_for_metric_key("reliability_rating", measures)
    sqale_index = get_value_for_metric_key("sqale_index", measures)
    sqale_rating = get_value_for_metric_key("sqale_rating", measures)

    period_index = 0
    period_details_table = ""

    if len(periods) > 0:
        period = periods[period_index]
        period_since = "previous version"
        if "parameter" in period:
            period_since = period["parameter"]
        else:
            if "mode" in period:
                period_since = period["mode"]
        period_started = period["date"]
        new_bugs = get_value_for_metric_key_and_period_index("new_bugs", measures, period_index)
        new_vulnerabilities = get_value_for_metric_key_and_period_index("new_vulnerabilities", measures, period_index)
        new_security_rating = get_value_for_metric_key_and_period_index("new_security_rating", measures, period_index)
        new_code_smells = get_value_for_metric_key_and_period_index("new_code_smells", measures, period_index)
        new_lines = get_value_for_metric_key_and_period_index("new_lines", measures, period_index)
        new_lines_to_cover = get_value_for_metric_key_and_period_index("new_lines_to_cover", measures, period_index)
        new_reliability_rating = get_value_for_metric_key_and_period_index("new_reliability_rating", measures,
                                                                           period_index)
        new_technical_debt = get_value_for_metric_key_and_period_index("new_technical_debt", measures, period_index)
        new_maintainability_rating = get_value_for_metric_key_and_period_index("new_maintainability_rating", measures,
                                                                               period_index)
        period_details_table += "<h3>Leak Period: since " + period_since + ", started " + period_started + "</h3>"
        period_details_table += "<table><tr><th>Issue Type</th><th>Value</th></tr>"
        period_details_table += "<tr><td>New Bugs</td><td>" + new_bugs + "</td></tr>"
        period_details_table += "<tr><td>New Vulnerabilities</td><td>" + new_vulnerabilities + "</td></tr>"
        period_details_table += "<tr><td>Security Rating on New Code</td><td>" + new_security_rating + "</td></tr>"
        period_details_table += "<tr><td>New Code Smells</td><td>" + new_code_smells + "</td></tr>"
        period_details_table += "<tr><td>New Lines</td><td>" + new_lines + "</td></tr>"
        period_details_table += "<tr><td>Lines to Cover on New Code</td><td>" + new_lines_to_cover + "</td></tr>"
        period_details_table += "<tr><td>Reliability Rating on New Code</td><td>" + new_reliability_rating + \
                                "</td></tr>"
        period_details_table += "<tr><td>Added Technical Debt</td><td>" + new_technical_debt + "</td></tr>"
        period_details_table += "<tr><td>Maintainability Rating on New Code</td><td>" + new_maintainability_rating + \
                                "</td></tr>"
        period_details_table += "</table><br>"

    quality_gate_details = get_value_for_metric_key("quality_gate_details", measures)
    quality_gate_details_table = ""
    if quality_gate_details:
        conditions = json.loads(quality_gate_details)["conditions"]
        if len(conditions) > 0:
            quality_gate_details_table += "<table><tr><th>Metric</th><th>Actual Value</th><th>Operand</th>" \
                                          "<th>Expected Value</th></tr>"
            for condition in conditions:
                quality_gate_details_table += "<tr>"
                if 'level' in condition and condition['level'] == "ERROR":
                    if 'metric' in condition:
                        metric_name = get_name_for_metric_key(condition['metric'], metrics)
                        quality_gate_details_table += "<td>" + metric_name + "</td>"
                    else:
                        quality_gate_details_table += "<td></td>"
                    if 'actual' in condition:
                        quality_gate_details_table += "<td>" + condition['actual'] + "</td>"
                    else:
                        quality_gate_details_table += "<td></td>"
                    if 'op' in condition:
                        quality_gate_details_table += "<td>" + condition['op'] + "</td>"
                    else:
                        quality_gate_details_table += "<td></td>"
                    if 'error' in condition:
                        quality_gate_details_table += "<td>" + condition['error'] + "</td>"
                    else:
                        quality_gate_details_table += "<td></td>"

            quality_gate_details_table += "</tr></table>"

    json_data = get_json(url, username, password, "/api/issues/search?componentKeys=" + component_key + "&statuses=OPEN&ps=1")
    if json_data['total'] == 0:
        print("no data returned - no report will be generated")
    else:
        print("found " + str(json_data['total']) + " issues. Report will be generated...")
        json_all = "["

        # GET ALL ISSUES (max. 500) OF TYPE VULNERABILITY
        json_vulnerabilities = get_json(url, username, password, 
            "/api/issues/search?componentKeys=" + component_key + "&statuses=OPEN&ps=500&types=VULNERABILITY")
        if json_vulnerabilities['total'] > 0:
            print("found " + str(json_vulnerabilities['total']) + " issues of type VULNERABILITY")
            json_vulnerabilities = filter_json(json_vulnerabilities)
            json_all += json_vulnerabilities

        # GET ALL ISSUS (max. 500) OF TYPE BUG
        json_bugs = get_json(url, username, password, "/api/issues/search?componentKeys=" + component_key + "&statuses=OPEN&ps=500&types=BUG")
        if json_bugs['total'] > 0:
            print("found " + str(json_bugs['total']) + " issues of type BUG")
            json_bugs = filter_json(json_bugs)
            if json_all != "[":
                json_all += ","
            json_all += json_bugs

        # GET ALL ISSUES (max. 500) OF TYPE CODE_SMELL
        json_codesmells = get_json(url, username, password, 
            "/api/issues/search?componentKeys=" + component_key + "&statuses=OPEN&ps=500&types=CODE_SMELL")
        if json_codesmells['total'] > 0:
            print("found " + str(json_codesmells['total']) + " issues of type CODE_SMELL")
            json_codesmells = filter_json(json_codesmells)
            if json_all != '[':
                json_all += ","
            json_all += json_codesmells

        json_all += "]"

        # GENERATE PDF
        json_data = json.loads(json_all)
        html_issues = ""

        for i in json_data:
            html_issues += "<tr>"
            if 'type' in i:
                html_issues += "<td>" + i['type'] + "</td>"
            else:
                html_issues += "<td></td>"
            if 'component' in i:
                component = i['component']
                component = component.split(":")[-1]
                html_issues += "<td>" + component + "</td>"
            else:
                html_issues += "<td></td>"
            if 'startLine' in i:
                html_issues += "<td>" + str(i['startLine']) + "</td>"
            else:
                html_issues += "<td></td>"
            if 'endLine' in i:
                html_issues += "<td>" + str(i['endLine']) + "</td>"
            else:
                html_issues += "<td></td>"
            if 'message' in i:
                html_issues += "<td>" + i['message'] + "</td>"
            else:
                html_issues += "<td></td>"
            html_issues += "</tr>"

        now_in_utc = datetime.datetime.utcfromtimestamp(datetime.datetime.now().timestamp())
        creation_date = str(now_in_utc) + " UTC"

        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template(TEMPLATE)
        template_vars = {"project": component_key, "server_version": server_version, "creation_date": creation_date,
                         "quality_gate_status": quality_gate_status, "bugs": bugs, "vulnerabilities": vulnerabilities,
                         "security_rating": security_rating, "code_smells": code_smells, "coverage": coverage,
                         "duplicated_blocks": duplicated_blocks, "duplicated_lines_density": duplicated_lines_density,
                         "ncloc": ncloc, "ncloc_language_distribution": ncloc_language_distribution,
                         "reliability_rating": reliability_rating, "sqale_index": sqale_index,
                         "sqale_rating": sqale_rating, "issue_table": html_issues,
                         "quality_gate_details_table": quality_gate_details_table, "project_name": project_name,
                         "project_organization": project_organization, "project_version": project_version,
                         "quality_gates_table": quality_gates_table, "quality_profiles_table": quality_profiles_table,
                         "project_analysis_date": project_analysis_date_utc}
        html_out = template.render(template_vars)
        report_name = "sonarqube_report_" + project_name + "_" + now_in_utc.strftime("%Y%m%d%H%M%S") + ".pdf"
        HTML(string=html_out, base_url=".").write_pdf(report_name, stylesheets=["style.css"])


def get_string(url, username, password, endpoint):
    url = url + endpoint
    r = requests.get(url, verify=False, auth=(username, password))
    return r.text


def get_json(url, username, password, endpoint):
    url = url + endpoint
    r = requests.get(url, verify=False, auth=(username, password))
    return json.loads(r.text)


def get_name_for_metric_key(metric_key, metrics):
    metric = next((item for item in metrics if item["key"] == metric_key), None)
    if metric:
        metric_name = metric.get("name")
        if metric_name:
            return metric_name


def get_value_for_metric_key(metric_key, measures):
    metric_measures = next((item for item in measures if item["metric"] == metric_key), None)
    if metric_measures:
        metric_value = metric_measures.get("value")
        if metric_value:
            return metric_value


def get_value_for_metric_key_and_period_index(metric_key, measures, period_index):
    metric_measures = next((item for item in measures if item["metric"] == metric_key), None)
    if metric_measures:
        metric_periods = metric_measures.get("periods")
        period_match = metric_periods[period_index]
        if period_match:
            return period_match.get("value")


# filters the json response of the API call
def filter_json(json_data):
    # select only the 'issues' key for filtering
    json_issues = json_data['issues']
    # we will filter the json with this keys for the target output
    json_keySet = ['component', 'author', 'message', 'effort', 'type']

    json_filtered = ''
    for issue in json_issues:
        json_filtered += '{'
        for key, value in issue.items():
            if key in json_keySet:
                # remove " in values - otherwise the target JSON is not valid
                value = value.replace('"', '')
                value = value.replace("'", '')
                strAttr = '\"' + key + '\":\"' + value + '\",'
                json_filtered += strAttr
            if key == 'textRange':
                for k, v in value.items():
                    if k == 'startLine' or k == 'endLine':
                        strAttr = '\"' + str(k) + '\":' + str(v) + ','
                        json_filtered += strAttr
        # removes the last , from the JSON string
        json_filtered = json_filtered[:-1]
        json_filtered += '},'
    # removes the last , from the JSON string
    json_filtered = json_filtered[:-1]
    return json_filtered


def main():
    argvLen = len(sys.argv)
    if argvLen == 5:
        url = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        component_key = sys.argv[4]
        print("API call for project: " + component_key + " will be executed")
        generate_report(url, username, password, component_key)
    else:
        print("Usage: python sonar_reporter.py <url> <usernmame> <password> <component_key>")


if __name__ == "__main__":
    main()
