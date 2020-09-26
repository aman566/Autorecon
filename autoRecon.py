# from urllib3.contrib import pyopenssl
from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory

import sys
import socket
# import json

from javax.swing import JMenuItem
from javax.swing import JFileChooser
from javax.swing import (
    JPanel,
    JList,
    AbstractListModel,
    JSplitPane,
    JButton,
    JTextField,
    JList,
    JTextPane,
    JScrollPane,
    JTextArea,
    JSeparator,
    ListSelectionModel,
    JLabel,
    JTable,
    JTabbedPane,
    JEditorPane,
    JScrollBar,
    BorderFactory,
    GroupLayout,
    LayoutStyle,
    SwingConstants,
    table,
)
from java.awt import FlowLayout
from java.util import List, ArrayList
from java.net import URL
from java.io import PrintWriter
from java.awt import Font, Color, Component

# create a StyledDocument for tab 1
from javax.swing.text import DefaultStyledDocument
from javax.swing.text import StyleContext, StyleConstants
from java.lang import Runnable

import threading
import censys.certificates

import logging
import json
import re
from urllib3.util import parse_url
import base64
import requests
import shodan
import time.sleep

#Add support for all cipher suites
# from urllib3.contrib import pyopenssl
# from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI

# Using the Runnable class for thread-safety with Swing


class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()


threadLocal = threading.local()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    EXTENSION_NAME = "AutoRecon"
    # subdomain = list()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.EXTENSION_NAME)

        callbacks.issueAlert("AutoRecon is enabled")

        # add the custom tab to Burp's UI
        self.initUI()
        # self._newpanel.setLayout(FlowLayout())
        # callbacks.customizeUiComponent(self._newpanel)
        callbacks.addSuiteTab(self)

        self.callable = [
            # self.sublister,
            # self.shodan_search,
            self.certsh_search,
            # self.anubis,
            # self.googleDig,
            # self.censys,
            # self.certspotter,
            # self.bufferover_run,
            # self.urlscan,
            # self.otx_alienvault,
            # self.threatminer,
            # self.netcraft,
            # self.threatcrowd,
            # self.dnsdumpster,
            # self.virustotal,
            # self.ptrarchive,
        ]
        # self.callable = [self.censys]

        # define stdout writer
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout.println(self.EXTENSION_NAME + " by @bourne")
        self._stdout.println(
            "================================================")
        self._stdout.println(
            'TIP: Right click on any domain and add it to scope in "autoRecon"'
        )
        self._stdout.println("")
        self.outputTxtArea.setText(
            self.EXTENSION_NAME
            + " by @bourne"
            + "\n"
            + "================================================"
            + "\n"
            + 'TIP: Right click on any domain and add it to scope in "autoRecon"\n'
        )

        self.context = None

        callbacks.registerContextMenuFactory(self)

        return

    def initUI(self):
        self.tab = JPanel()

        # UI for Output
        self.outputLabel = JLabel("AutoRecon Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255, 102, 52))
        self.logPane = JScrollPane()
        self.outputTxtArea = JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = JFileChooser()

        # Layout
        layout = GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup().addGroup(
                layout.createSequentialGroup().addGroup(
                    layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

        layout.setVerticalGroup(
            layout.createParallelGroup().addGroup(
                layout.createParallelGroup().addGroup(
                    layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        """Name of our tab"""
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
        self.outputTxtArea.setText(
            self.EXTENSION_NAME
            + " by @bourne"
            + "\n"
            + "================================================"
            + "\n"
            + 'TIP: Right click on any domain and add it to scope in "autoRecon"\n'
        )

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to : " + filename)
        open(filename, "w", 0).write(self.outputTxtArea.text)

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(
            JMenuItem(
                "Add domain to scope for AutoRecon", actionPerformed=self.threadAnalysis
            )
        )
        return menu_list

    def threadAnalysis(self, event):
        http_traffic = self.context.getSelectedMessages()

        self._stdout.println(str(len(http_traffic)) + " requests highlighted")

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            if host.startswith("www."):
                host = host[4:]

            self._stdout.println("User selected host: " + str(host))

        self.subdomain = list()
        threads = []
        for i in self.callable:
            time.sleep(1)
            thread = threading.Thread(target=i, args=(host,))
            # thread.daemon = True
            threads.append(thread)
            thread.start()

        for i in threads:
            i.join()

        self.outputTxtArea.setText(
            self.EXTENSION_NAME
            + " by @bourne"
            + "\n"
            + "================================================"
            + "\n"
            + 'TIP: Right click on any domain and add it to scope in "autoRecon"\n'
        )
        self.outputTxtArea.append("\n DOMAIN: "+host)
        self.outputTxtArea.append("\n Total {} subdomains found :\n\n".format(len(set(self.subdomain))))
        for s in set(self.subdomain):
            if not "*" in s:
                self.outputTxtArea.append("\n" + s)
                # request_url = """https://api.viewdns.info/portscan/?host={}&apikey=3b59ef16aea9a71c7e6ae2872e83008493375e9e&output=json""".format(
                #     s
                # )
                # try:
                #     # self.outputTxtArea.append(request_url)
                #     time.sleep(2)
                #     req = requests.get(request_url, verify=False, headers=self.headers, timeout=3)
                #     req = json.loads(req.text)
                # except Exception as e:
                #     self.outputTxtArea.append(str(e))
                    
                # for i in req["response"]["port"]:
                #     if i["status"] == "open":
                #         self.outputTxtArea.append("\n\t",i["number"],i["service"])
                

                try:
                    req = requests.get("""http://web.archive.org/cdx/search/cdx?url=*.{0}/*
                                    &output=json&fl=original&collapse=urlkey&page=/""".format(
                                        s
                                    ), verify=False, headers=self.headers, timeout=3)
                    temp = []
                    t = json.loads(req.text)
                    for i in t:
                        temp.extend(i)
                except Exception:
                    pass
                paths = []
                count = 0
                for i in range(1, len(temp)):
                    not_contains = re.compile(
                        "|".join(["js","txt", "git","zip"])
                    )
                    # print(type(temp[i]))

                    if temp[i] not in paths and not_contains.search(
                        temp[i]
                    ):
                        paths.append(temp[i])
                        count += 1
                for i in paths:
                    if ".js" in i.lower() or ".zip" in i.lower() or ".txt" in i.lower() or ".git" in i.lower():
                        self.outputTxtArea.append("\n\t"+i)


        # thread = threading.Thread(target=self.certsh_search, args=(host,))
        # thread.daemon = True
        # thread.start()

        # thread = threading.Thread(target=self.shodan_search, args=(host,))
        # thread.daemon = True
        # thread.start()

    def certsh_search(self, host):
        BASE_URL = "https://crt.sh"
        threadLocal.response = requests.get(
            BASE_URL + "/?q=%." + host + "&output=json")
        # self._stdout.println(threadLocal.response)
        threadLocal.result = threadLocal.response.json()
        # self._stdout.println(result)
        threadLocal.sub = []

        for item in threadLocal.result:
            s = item["name_value"]
            t = s.split("\n")
            self.subdomain.extend(t)
            # self.subdomain.append(s)
            # self._stdout.println(item)
            self._stdout.println(self.subdomain)
            self._stdout.println("....")
            if s not in threadLocal.sub:
                threadLocal.sub.append(s)
                self._stdout.println(s)
        return

    def shodan_search(self, host):
        BASE_URL = "https://api.shodan.io/shodan/host/search/"
        SHODAN_API_KEY = "J1Rp7W8tcqmhsdiB3ZU3JVhOlPpOHp8X"
        API = "WozM2OXwuUSMSsiseIkPtyLFxYnDUrPP"
        QUERY = "hostname"

        try:
            threadLocal.response = requests.get(
                "https://api.shodan.io/shodan/host/search?key="
                + SHODAN_API_KEY
                + "&query=hostname:"
                + host
            )
            # self._stdout.println(response.text)
            threadLocal.result = threadLocal.response.json()
            # self._stdout.println(result)
            threadLocal.sub = []
            for item in threadLocal.result["matches"]:
                s = item["hostnames"][0]
                self.subdomain.append(s)
                if s not in threadLocal.sub:
                    threadLocal.sub.append(s)
                    self._stdout.println(s)
            return
        except Exception as error:
            logging.exception("message")

    def anubis(self, host):
        BASE_URL = "https://jldc.me/anubis/subdomains/{0}".format(host)

        try:
            threadLocal.response = requests.get(BASE_URL)
            threadLocal.sub = []
            results = json.loads(threadLocal.response.text)
            for w in results:
                if "*" not in w and w.endswith("." + host) and w not in threadLocal.sub:
                    threadLocal.sub.append(w)
                    self.subdomain.append(w)
                    self._stdout.println(w)
            return
        except Exception as error:
            logging.exception("message")

    def bufferover_run(self, host):
        try:
            threadLocal.response = requests.get(
                "http://dns.bufferover.run/dns?q={0}".format(host)
            )
            threadLocal.sub = []
            results = json.loads(threadLocal.response.text)["FDNS_A"]
            for w in results:
                domain = w.split(",")[1]
                if (
                    "*" not in domain
                    and domain.endswith("." + host)
                    and domain not in threadLocal.sub
                ):
                    threadLocal.sub.append(domain)
                    self.subdomain.append(domain)
                    self._stdout.println(domain)
            return
        except Exception as error:
            logging.exception("message")

    def urlscan(self, host):
        BASE_URL = "https://urlscan.io/api/v1/search/?q=domain:{0}".format(
            host)

        try:
            threadLocal.response = requests.get(BASE_URL)
            threadLocal.sub = []
            results = json.loads(threadLocal.response.text)["results"]
            for w in results:
                domain = w["page"]["domain"]
                if (
                    "*" not in domain
                    and domain.endswith("." + host)
                    and domain not in threadLocal.sub
                ):
                    threadLocal.sub.append(domain)
                    self.subdomain.append(domain)
                    self._stdout.println(domain)
            return
        except Exception as error:
            logging.exception("message")

    def otx_alienvault(self, host):
        BASE_URL = "https://otx.alienvault.com/api/v1/indicator/domain/{0}/passive_dns".format(
            host
        )

        try:
            tHeader = {
                "Host": "otx.alienvault.com",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0",
            }

            response = requests.get(BASE_URL)
            threadLocal.sub = []
            self._stdout.println(response.status_code)
            # results = json.loads(threadLocal.response.text)["passive_dns"]
            # for w in results:
            #     h = w["hostname"]
            #     if "*" not in h and h.endswith("." + host) and h not in threadLocal.sub:
            #         threadLocal.sub.append(h)
            #         self.subdomain.append(h)
            #         self._stdout.println(h)
            return
        except Exception as error:
            logging.exception("message")

    def threatminer(self, host):
        BASE_URL = "https://api.threatminer.org/v2/domain.php?q={0}&api=True&rt=5".format(
            host
        )

        try:
            threadLocal.response = requests.get(BASE_URL)
            threadLocal.sub = []
            results = json.loads(threadLocal.response.text)["results"]
            for w in results:
                if "*" not in w and w.endswith("." + host) and w not in threadLocal.sub:
                    threadLocal.sub.append(w)
                    self.subdomain.append(w)
                    self._stdout.println(w)
            return
        except Exception as error:
            logging.exception("message")

    # def censys(self, host):
    #     try:
    #         censys_certificates = censys.certificates.CensysCertificates(
    #             api_id="5d63a69e-6142-46ec-830f-7279734e76f0", api_secret="qz6uDnlOCfZPJIXVyKvheot5HUxqZjNl")
    #         certificate_query = 'parsed.names: %s' % host
    #         certificates_search_results = censys_certificates.search(
    #             certificate_query, fields=['parsed.names'])

    #         subdomains = []
    #         for search_result in certificates_search_results:
    #             subdomains.extend(search_result['parsed.names'])
    #             self._stdout.println(search_result['parsed.names'])
    #     except Exception as error:
    #         self._stderr.println(error)
                    
    #     return threadLocal.subs

    def certspotter(self, host):
        BASE_URL = "https://certspotter.com/api/v0/certs?domain={0}".format(
            host)

        try:
            threadLocal.response = requests.get(BASE_URL)
            threadLocal.sub = []
            if threadLocal.response.status_code == 200:
                for w in (
                    threadLocal.response.content.replace('"', " ")
                    .replace("'", " ")
                    .rsplit()
                ):
                    if (
                        "*" not in w
                        and w.endswith("." + host)
                        and w not in threadLocal.sub
                    ):
                        threadLocal.sub.append(w)
                        self.subdomain.append(w)
                        self._stdout.println(w)
            return
        except Exception as error:
            logging.exception("message")

    def googleDig(self, host):
        try:
            url_1 = "https://toolbox.googleapps.com/apps/dig/#ANY/"
            url_2 = "https://toolbox.googleapps.com/apps/dig/lookup"
            s = requests.session()
            threadLocal.req = s.get(url_1)
            csrf_middleware = re.compile(
                "<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />", re.S
            ).findall(threadLocal.req.content)[0]
            # tHeader = self.headers
            # tHeader["Referer"] = url_1
            threadLocal.req = s.post(
                url_2,
                cookies={"csrftoken": csrf_middleware},
                data={
                    "csrfmiddlewaretoken": csrf_middleware,
                    "domain": host,
                    "typ": "ANY",
                },
                headers={"Referer": url_1},
                verify=False,
            )
            threadLocal.subs = []
            if threadLocal.req.status_code is 200:
                for w in (
                    json.loads(threadLocal.req.content)["response"]
                    .replace('"', " ")
                    .replace(";", " ")
                    .rsplit()
                ):
                    if (
                        "*" not in w
                        and w.endswith("." + host + ".")
                        and w[:-1] not in threadLocal.subs
                    ):
                        threadLocal.subs.append(w[:-1])
                        self.subdomain.append(w[:-1])
            else:
                # warn 403
                pass
        except Exception as error:
            logging.exception("message")
        return threadLocal.subs

    def netcraft(self, host):
        try:
            threadLocal.n = 0
            threadLocal.results = ""
            url = (
                "https://searchdns.netcraft.com/?restriction=site+contains&host=*.{0}"
                "&lookup=wait..&position=limited".format(host)
            )

            threadLocal.subs = []
            while "<b>Next page</b></a>" not in threadLocal.results:
                while 1:
                    try:
                        threadLocal.results = requests.get(url)
                        break
                    except:
                        threadLocal.n += 1
                        if threadLocal.n is 3:
                            break
                if threadLocal.n is 3:
                    break
                if threadLocal.results.status_code is 200:
                    for l in re.compile(
                        '<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">'
                    ).findall(threadLocal.results.content):
                        domain = parse_url(l).host

                        if (
                            "*" not in domain
                            and domain.endswith("." + host)
                            and domain not in threadLocal.subs
                        ):
                            threadLocal.subs.append(domain)
                            self.subdomain.append(domain)
                else:
                    # warn 403
                    break
                try:
                    url = (
                        "http://searchdns.netcraft.com"
                        + re.compile('<A href="(.*?)"><b>Next page</b></a>').findall(
                            threadLocal.results.content
                        )[0]
                    )
                except:
                    break
        except Exception as error:
            logging.exception("message")
        return threadLocal.subs

    def threatcrowd(self, host):
        try:
            threadLocal.n = 0
            url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}".format(
                host
            )
            threadLocal.subs = []
            while 1:
                try:
                    threadLocal.results = requests.get(url)
                    break
                except:
                    threadLocal.n += 1
                    if threadLocal.n is 3:
                        break
            if threadLocal.results.status_code is 200:
                try:
                    threadLocal.subs = json.loads(threadLocal.results.content)[
                        "subdomains"
                    ]
                    for i in threadLocal.subs:
                        self.subdomain.append(i)
                except:
                    threadLocal.subs = []
            else:
                # warn 403
                pass
            return threadLocal.subs
        except Exception as error:
            logging.exception("message")
        

    def dnsdumpster(self, host):
        try:
            url = "https://dnsdumpster.com/"
            s = requests.session()
            threadLocal.req = s.get(url)
            csrf_middleware = re.compile(
                "<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />", re.S
            ).findall(threadLocal.req.content)[0]
            threadLocal.req = s.post(
                url,
                cookies={"csrftoken": csrf_middleware},
                data={"csrfmiddlewaretoken": csrf_middleware, "targetip": host},
                headers={"Referer": url},
            )
            threadLocal.subs = []
            if threadLocal.req.status_code is 200:
                for w in (
                    threadLocal.req.content.replace(".<", " ")
                    .replace("<", " ")
                    .replace(">", " ")
                    .rsplit()
                ):
                    if (
                        "*" not in w
                        and w.endswith("." + host)
                        and w not in threadLocal.subs
                    ):
                        threadLocal.subs.append(w)
                        self.subdomain.append(w)
            else:
                # warn 403
                pass
        except Exception as error:
            logging.exception("message")
        return threadLocal.subs

    def virustotal(self, host):
        n = 0
        url = "https://www.virustotal.com/en/domain/{0}/information/".format(
            host)
        threadLocal.subs = []
        try:
            threadLocal.results = requests.get(url, headers=headers)
            if threadLocal.results.status_code is 200:
                try:
                    for l in re.compile(
                        '<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>',
                        re.S,
                    ).findall(threadLocal.results.content):
                        domain = parse_url(l).host
                        if (
                            "*" not in domain
                            and domain.strip().endswith("." + host)
                            and domain.strip() not in threadLocal.subs
                        ):
                            threadLocal.subs.append(domain.strip())
                except:
                    pass
            else:
                # warn 403
                pass
        except:
            pass
        return threadLocal.subs

    def ptrarchive(self, host):
        n = 0
        url = "http://ptrarchive.com/tools/search2.htm?label={0}&date=ALL".format(
            host)
        threadLocal.subs = []
        try:
            threadLocal.results = requests.get(url, headers=headers)
            if threadLocal.results.status_code is 200:
                for sub in threadLocal.results.content.rsplit():
                    if (
                        "*" in sub
                        and sub.endswith("." + host)
                        and sub not in threadLocal.subs
                    ):
                        threadLocal.subs.append(sub)
            else:
                # warn 403
                pass
        except:
            pass
        return threadLocal.subs

    def sublister(self, host):
        BASE_URL = "https://api.sublist3r.com/search.php?domain={0}".format(
            host)

        try:
            threadLocal.response = requests.get(BASE_URL)
            threadLocal.sub = []
            if threadLocal.response.status_code == 200:
                for w in (
                    json.loads(threadLocal.response.text)
                ):
                    if (
                        "*" not in w
                        and w.endswith("." + host)
                        and w not in threadLocal.sub
                    ):
                        threadLocal.sub.append(w)
                        self.subdomain.append(w)
                        self._stdout.println(w)
            return
        except Exception as error:
            logging.exception("message")
