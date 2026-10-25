"""Investigation guidance: for each kind of finding, what it is, why attackers use
it, when it's usually harmless, and the next steps to confirm or rule it out.

Steps carry an `action` string that the GUI dispatches (e.g. "pdf.search:/AA")
and a `cli` string showing the equivalent command, so analysts learn the CLI
tools while using the GUI. Placeholders like {keyword} and {object} are filled
from the finding's ref dict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding


@dataclass
class Step:
    """One next step: what to do, the GUI action that does it, and the equivalent command."""
    label: str
    action: str = ""      # "" = manual step (read/think), no button
    cli: str = ""


@dataclass
class Guide:
    """What a finding means, why attackers use it, when it's harmless, and what to do next."""
    title: str
    what: str
    why: str = ""
    benign: str = ""
    steps: list[Step] = field(default_factory=list)


S = Step  # brevity in the table below

# --------------------------------------------------------------------------- PDF
_PDF_TRIGGER_STEPS = [
    S("Open Triggers & actions to see what runs, when, and from which object", "pdf.triggers",
      "pdf-parser.py -s {keyword} sample.pdf"),
    S("List every object containing {keyword}", "pdf.search:{keyword}", "pdf-parser.py -s {keyword} sample.pdf"),
    S("Click the action reference in the dictionary to follow it (N 0 R links are clickable)", ""),
    S("If the action is JavaScript, open its stream with filters applied", "pdf.triggers",
      "pdf-parser.py -o <id> -f -d js.txt sample.pdf"),
    S("Select the JavaScript object, then load it into the JS workbench (beautify, decode %u / \\x payloads)",
      "js.workbench"),
    S("Cross-check with peepdf (suspicious elements, known CVEs)", "peepdf.run", "peepdf -f -l -j sample.pdf"),
]

GUIDES: dict[str, Guide] = {
    "pdf:/JS": Guide(
        "JavaScript in the PDF",
        "/JS holds JavaScript code, inline or in a stream, that Acrobat runs when an action fires.",
        "Most PDF exploits and many droppers run through JavaScript: heap sprays, exploit triggers, "
        "or code that decodes and launches an embedded payload.",
        "Fillable forms use small scripts for number/date formatting and totals "
        "(AFNumber_Format, AFSimple_Calculate, AFDate_FormatEx). Those are standard Acrobat calls.",
        _PDF_TRIGGER_STEPS),
    "pdf:/JavaScript": Guide(
        "JavaScript action or name tree",
        "/JavaScript marks a JavaScript action (/S /JavaScript) or the document-level script tree in /Names.",
        "Document-level scripts run as soon as the file opens, with no click needed.",
        "Same as /JS: form formatting/calculation scripts are common in legitimate forms.",
        _PDF_TRIGGER_STEPS),
    "pdf:/OpenAction": Guide(
        "Action when the document opens",
        "/OpenAction runs something automatically when the PDF is opened.",
        "Paired with JavaScript or /Launch it gives code execution on open; paired with /URI it "
        "can push the reader to a phishing page.",
        "Very often it's just a destination like [3 0 R /Fit] that opens at page 1 or sets the zoom. "
        "That's harmless.",
        [S("See what the OpenAction points to", "pdf.triggers", "pdf-parser.py -s /OpenAction sample.pdf"),
         S("List objects containing /OpenAction", "pdf.search:/OpenAction", "pdf-parser.py -s /OpenAction sample.pdf"),
         S("If the target is an array like [N 0 R /Fit], it is page navigation: benign", ""),
         S("If the target is an action with /S /JavaScript or /Launch, open the payload object", "pdf.triggers")]),
    "pdf:/AA": Guide(
        "Additional actions (/AA)",
        "/AA attaches actions to events: a page opening or closing, a form field being clicked, typed "
        "into, formatted, validated or calculated, or the document being printed, saved or closed.",
        "Attackers use /AA to run JavaScript or launch commands without an obvious /OpenAction, for "
        "example when page 1 becomes visible.",
        "Fillable forms use /AA on fields for formatting (K/F keys) and totals (C key), with standard "
        "AF* functions. A form with many /AA entries and no other indicators is usually benign.",
        [S("Open Triggers & actions: each /AA entry with its event, target action and payload", "pdf.triggers",
           "pdf-parser.py -s /AA sample.pdf"),
         S("List objects containing /AA", "pdf.search:/AA", "pdf-parser.py -s /AA sample.pdf"),
         S("Check the event keys: Page O/C (open/close), field K/F/V/C (keystroke/format/validate/"
           "calculate), document WC/WS/DS/WP/DP (close/save/print)", ""),
         S("Open the JavaScript behind any trigger and look for AF* formatting calls (benign) vs "
           "eval, unescape, util.printf, this.exportDataObject or app.launchURL", "pdf.triggers",
           "pdf-parser.py -o <id> -f sample.pdf"),
         S("Load the selected object's script into the JS workbench", "js.workbench")]),
    "pdf:/Launch": Guide(
        "Launch action",
        "/Launch tells the reader to open a file or run a program (/F or /Win /F).",
        "A direct path to command execution (cmd.exe, powershell, mshta, an embedded .exe). Modern "
        "Acrobat warns the user first, but social engineering in the PDF often tells them to click Open.",
        "Rare in legitimate documents. Occasionally used to open another document in the same folder.",
        [S("See the launch target", "pdf.triggers", "pdf-parser.py -s /Launch sample.pdf"),
         S("List objects containing /Launch", "pdf.search:/Launch", "pdf-parser.py -s /Launch sample.pdf"),
         S("Record the command line as an IOC; look for an /EmbeddedFile it may launch", "pdf.search:/EmbeddedFile")]),
    "pdf:/EmbeddedFile": Guide(
        "Embedded file",
        "The PDF carries a file attachment inside a stream.",
        "Droppers hide an executable, script or macro document inside and use JavaScript "
        "(exportDataObject) or /Launch to open it.",
        "Portfolios and engineering documents sometimes attach spreadsheets or CAD files legitimately.",
        [S("List the embedded file objects", "pdf.search:/EmbeddedFile", "pdf-parser.py -s /EmbeddedFile sample.pdf"),
         S("Select the object, open its stream with filters, then 'Analyze stream as new sample'",
           "pdf.search:/EmbeddedFile", "pdf-parser.py -o <id> -f -d embedded.bin sample.pdf"),
         S("Check whether JavaScript calls exportDataObject or a /Launch opens it", "pdf.triggers")]),
    "pdf:/URI": Guide(
        "Links (/URI)",
        "/URI actions open a web address when clicked, or automatically if triggered by an /OpenAction or /AA.",
        "The most common phishing PDF: a fake document with a 'View document' button linking to a "
        "credential-harvesting page or a malware download.",
        "Normal documents contain links too. Judge by the domain, not the presence of a link.",
        [S("See which links fire automatically vs on click", "pdf.triggers"),
         S("List all link objects", "pdf.search:/URI", "pdf-parser.py -s /URI sample.pdf"),
         S("Review the domains in the Report tab IOCs; check them against threat intel before blocking", "report")]),
    "pdf:/AcroForm": Guide(
        "Interactive form (/AcroForm)",
        "The document has fillable form fields.",
        "Forms are a common place to hang JavaScript (field actions) and XFA content.",
        "On its own, a form is normal: applications, timesheets, qualification sheets.",
        [S("Check whether any field has actions that run JavaScript", "pdf.triggers"),
         S("If there is no JavaScript, Launch or XFA, this is very likely just a form", "")]),
    "pdf:/XFA": Guide(
        "XFA form",
        "XML Forms Architecture: the form is defined in XML that can contain its own scripts.",
        "XFA has a long exploit history and can hide JavaScript outside the usual /JS keys.",
        "Some government and enterprise forms (LiveCycle Designer) use XFA legitimately.",
        [S("Find the XFA objects", "pdf.search:/XFA", "pdf-parser.py -s /XFA sample.pdf"),
         S("Decode the XFA streams and search for <script> blocks", "pdf.builder:--searchstream=script -f",
           "pdf-parser.py --searchstream=script -f sample.pdf")]),
    "pdf:/JBIG2Decode": Guide(
        "JBIG2 image filter",
        "A compression filter for black-and-white images.",
        "Several Acrobat and Foxit exploits (and FORCEDENTRY on iOS) abused JBIG2 decoder bugs.",
        "Scanned documents legitimately use JBIG2.",
        [S("Find the JBIG2 streams", "pdf.search:/JBIG2Decode", "pdf-parser.py -s /JBIG2Decode sample.pdf"),
         S("Check peepdf for known-vulnerable elements", "peepdf.run")]),
    "pdf:/RichMedia": Guide(
        "Embedded Flash / rich media",
        "Flash or other rich media is embedded.",
        "Flash was a major exploit vector; any Flash in a recent PDF is suspicious.",
        "Old interactive brochures.",
        [S("Find the RichMedia objects", "pdf.search:/RichMedia", "pdf-parser.py -s /RichMedia sample.pdf"),
         S("Extract the SWF stream and analyze it as a new sample", "pdf.search:/RichMedia")]),
    "pdf:/ObjStm": Guide(
        "Object streams",
        "Objects are stored compressed inside other streams (PDF 1.5+).",
        "Hides keywords from simple scanners like pdfid. The other tabs parse inside them.",
        "Standard in PDFs from Word, Chrome, Acrobat and most modern tools.",
        [S("pdf-parser already expands object streams (-O); review its Triggers & actions", "pdf.triggers",
           "pdf-parser.py -O sample.pdf")]),
    "pdf:/Encrypt": Guide(
        "Encrypted PDF",
        "Strings and streams are encrypted (often with an empty user password, just to restrict editing).",
        "Encryption hides JavaScript and URLs from static scanners.",
        "Many legitimate PDFs are 'encrypted' only to prevent editing or printing.",
        [S("Decrypt it: a readable copy (.bin) opens as a new sample, and every tool re-runs on it",
           "pdf.decrypt", "qpdf --decrypt sample.pdf decrypted.pdf"),
         S("peepdf decrypts empty-password PDFs itself; run its overview", "peepdf.run", "peepdf -f -l -j sample.pdf"),
         S("Use the peepdf console: 'info', then 'js_code <id>' on suspicious objects", "peepdf.console:info")]),
    "pdf:encrypted_unreadable": Guide(
        "Encrypted PDF: contents unreadable",
        "pdf-parser can't decrypt, so script text, link targets and streams it shows are ciphertext. Its "
        "trigger list still shows the structure (what fires, and when), but not what the code does.",
        "Encrypting with an empty password costs the attacker nothing and blinds most static scanners.",
        "Many legitimate PDFs are encrypted only to restrict editing or printing.",
        [S("Decrypt it: a readable copy (.bin) opens as a new sample, and every tool re-runs on it",
           "pdf.decrypt", "qpdf --decrypt sample.pdf decrypted.pdf"),
         S("Meanwhile, review what fires automatically", "pdf.triggers", "pdf-parser.py -a -O sample.pdf"),
         S("If decryption asks for a password, look for it in the email that delivered the file", "")]),
    "pdf:/SubmitForm": Guide(
        "Form submission",
        "Form data can be sent to a remote URL.",
        "Credential-phishing forms post what the victim types to the attacker.",
        "Legitimate online forms submit to the organization's server.",
        [S("Find the submit target", "pdf.triggers"), S("List objects", "pdf.search:/SubmitForm")]),
    "pdf:/GoToR": Guide("Jump to remote document", "Opens another (remote) document.",
                        "Can be used to fetch a remote file or leak NTLM hashes via a UNC path.", "",
                        [S("Find the target", "pdf.search:/GoToR", "pdf-parser.py -s /GoToR sample.pdf")]),
    "pdf:/GoToE": Guide("Jump to embedded document", "Opens a document embedded in this PDF.",
                        "Hides a second malicious document inside the first.", "",
                        [S("Find the embedded target", "pdf.search:/GoToE"),
                         S("Extract embedded files", "pdf.search:/EmbeddedFile")]),
    "pdf:/Colors > 2^24": Guide("Abnormal /Colors value", "An image parameter with an impossibly large value.",
                                "Signature of an old Acrobat integer overflow exploit (CVE-2009-3459).", "",
                                [S("Run peepdf for vulnerability matches", "peepdf.run")]),
    "pdf:after_eof": Guide(
        "Data after the end of the PDF",
        "Bytes exist after the final %%EOF marker.",
        "Appended payloads, polyglots (PDF + ZIP/HTA/JAR), or a second document.",
        "Incremental saves, or a few bytes of padding from some generators.",
        [S("Select the bytes after the last %%EOF in the hex view", "hex:after_eof"),
         S("Identify them: Hex tab → 'Analyze selection as new sample' (a zip, HTA or second document is "
           "malicious; a few bytes of padding are not)", "hex:after_eof"),
         S("Or keep a copy: Hex tab → 'Save selection…'", "hex:after_eof")]),
    "pdf:no_header": Guide("No PDF header", "pdfid did not find %PDF in the first 1 KB.",
                           "Could be a disguised file or a damaged PDF.", "",
                           [S("Re-run pdfid with Force (-f)", "pdfid.builder:-f -e", "pdfid.py -f -e sample.pdf")]),
    "pdf:trigger_js": Guide(
        "Automatic JavaScript",
        "A trigger runs JavaScript (see the trigger and payload object in the detail).",
        "This is the execution path most PDF malware uses.",
        "Standard AF* form formatting/calculation scripts on fields are benign.",
        [S("Open the payload object and decode it", "pdf.object:{payload}", "pdf-parser.py -o {payload} -f sample.pdf"),
         S("Load the script into the JS workbench (beautified; then try Unescape payload)", "pdf.js:{payload}",
           "pdf-parser.py -o {payload} -f -d script.js sample.pdf"),
         S("Look for eval, unescape, String.fromCharCode, util.printf, exportDataObject, launchURL", "")]),
    "pdf:trigger_launch": Guide(
        "Automatic Launch", "A trigger launches a program or file.", "Direct command execution path.", "",
        [S("Open the action object", "pdf.object:{object}", "pdf-parser.py -o {object} sample.pdf")]),
    "pdf:vuln": Guide(
        "Known-vulnerable element",
        "peepdf matched an element associated with a published exploit (CVE).",
        "Exploit documents target exactly these elements.",
        "Matches are heuristic: the element can appear in benign files.",
        [S("Open the peepdf overview and note the object numbers", "peepdf.run"),
         S("Inspect those objects in pdf-parser", "pdf.triggers")]),
    "pdf:peepdf_element": Guide(
        "Element flagged by peepdf",
        "peepdf lists this name among its suspicious elements.",
        "See the matching pdfid keyword guidance.", "",
        [S("Open the objects in pdf-parser", "pdf.search:{keyword}", "pdf-parser.py -s {keyword} sample.pdf"),
         S("Check Triggers & actions", "pdf.triggers")]),

    # ----------------------------------------------------------------------- Office
    "office:mraptor_suspicious": Guide(
        "mraptor: SUSPICIOUS macros",
        "The macros run automatically (A) and can write files (W) and/or execute commands (X).",
        "This is the classic macro-dropper pattern: Document_Open, then download or decode a payload, "
        "then run it.",
        "Some business automation does all three, but it's rare in documents arriving by email.",
        [S("Read the macro code: flagged keywords are highlighted red", "macros.view:source", "olevba sample.doc"),
         S("Check the Analysis table for AutoExec and Suspicious keywords", "macros.tab:analysis",
           "olevba -a sample.doc"),
         S("Switch to 'Revealed' to see obfuscated strings decoded", "macros.view:revealed",
           "olevba --decode --reveal sample.doc"),
         S("Collect URLs and paths from the IOCs tab", "macros.tab:iocs"),
         S("Check for VBA stomping (source vs p-code)", "macros.tab:pcode", "olevba --show-pcode sample.doc")]),
    "office:mraptor_ok": Guide(
        "Macros present (mraptor OK)",
        "The file has macros, but mraptor's rules didn't find AutoExec + Write/Execute together.",
        "mraptor can be evaded (e.g. execution via a button, or obfuscated keywords).",
        "Templates and business spreadsheets often contain harmless macros.",
        [S("Read the code anyway", "macros.view:source", "olevba sample.doc"),
         S("Check for stomping, which hides real code from source-based checks", "macros.tab:pcode")]),
    "office:xlm": Guide(
        "Excel 4.0 (XLM) macros",
        "Old-style macro formulas on (often hidden or very hidden) macro sheets.",
        "Heavily abused because many tools ignore them; formulas are built from CHAR() pieces at runtime.",
        "Almost never legitimate in modern files.",
        [S("View the XLM formulas olevba extracted", "macros.tab:xlm", "olevba sample.xls"),
         S("Emulate the XLM to recover URLs and EXEC/CALL targets", "macros.emulate",
           "xlmdeobfuscator --file sample.xls"),
         S("List BIFF records with oledump's plugin_biff", "streams.builder:-p plugin_biff.py --pluginoptions -x",
           "oledump.py -p plugin_biff.py --pluginoptions -x sample.xls")]),
    "vba:autoexec": Guide(
        "Macro runs automatically",
        "An AutoExec entry point (AutoOpen, Document_Open, Workbook_Open, Auto_Close…) runs code without a click.",
        "Every macro dropper needs one.", "Business macros sometimes use Workbook_Open to set things up.",
        [S("Jump to the entry point in the code", "macros.keyword:{keyword}", "olevba sample.doc"),
         S("Follow what it calls: look for Shell, CreateObject, URLDownloadToFile, PowerShell",
           "macros.tab:analysis")]),
    "vba:suspicious": Guide(
        "Suspicious macro keywords",
        "Calls commonly used to download, write or execute: Shell, CreateObject, WScript, XMLHTTP, "
        "ADODB.Stream, Environ, Chr()-based obfuscation.",
        "Together they show what the macro does to the system.", "Individually many are used by legitimate automation.",
        [S("Filter the Analysis table to Suspicious", "macros.tab:analysis", "olevba -a sample.doc"),
         S("Double-click a keyword to find it in the code", "macros.tab:analysis")]),
    "vba:ioc": Guide(
        "Indicator in macro code", "olevba extracted a URL, IP, executable name or path from the code.",
        "Usually the payload download location or dropped file name.", "",
        [S("Review all IOCs", "macros.tab:iocs"), S("Add them to your block list via the Report tab", "report")]),
    "vba:stomping": Guide(
        "VBA stomping",
        "The compiled p-code doesn't match the VBA source text.",
        "Attackers replace the source with harmless code while the p-code (which Office actually runs on "
        "the matching version) stays malicious. Source-based tools then miss it.",
        "Rarely, version mismatches cause false positives.",
        [S("Read the p-code disassembly; that's what really runs", "macros.tab:pcode", "pcodedmp sample.doc"),
         S("Compare against the source view", "macros.view:source")]),
    "vba:encoded": Guide(
        "Encoded strings", "Hex, Base64 or Dridex-style encoded strings were found in the macros.",
        "Used to hide URLs and commands from scanners.", "",
        [S("See decoded values in the Analysis table", "macros.tab:analysis", "olevba --decode sample.doc"),
         S("Switch the code view to Revealed", "macros.view:revealed", "olevba --reveal sample.doc")]),
    "xlm:ioc": Guide("URL recovered from XLM emulation", "Emulating the Excel 4.0 macros produced this URL.",
                     "Typically the second-stage download.", "",
                     [S("Review the emulation output", "macros.tab:xlm"), S("Add to block list", "report")]),
    "xlm:exec": Guide("XLM calls the OS", "The emulated formulas use EXEC, CALL or REGISTER.",
                      "These run commands or call Win32 APIs (e.g. URLDownloadToFileA, ShellExecute).", "",
                      [S("Review the emulation output", "macros.tab:xlm")]),
    "oleid:ext_rels": Guide(
        "External relationships",
        "The document loads content from outside itself when opened.",
        "Remote template injection: a clean .docx fetches a macro-enabled template from the attacker's "
        "server, bypassing attachment scanning.",
        "Hyperlinks are external relationships too, and are normal.",
        [S("Open the Relationships list in the Parts tab", "parts.rels"),
         S("Look for attachedTemplate, oleObject or frame targets (high risk) vs hyperlink (normal)", "parts.rels")]),
    "oleid:ObjectPool": Guide(
        "Embedded OLE objects", "An ObjectPool storage holds embedded objects.",
        "Embedded executables, scripts or packaged files (Ole10Native) dropped on double-click.", "",
        [S("Extract the objects", "objects.extract", "oleobj -d out sample.doc"),
         S("See the streams marked O in oledump", "streams.list", "oledump.py sample.doc")]),
    "oleid:encrypted": Guide(
        "Encrypted document", "The content is encrypted with a password.",
        "Encryption defeats email scanning; the password is usually in the email body.",
        "Legitimately protected business documents.",
        [S("Decrypt it (Excel's default password is tried first)", "macros.decrypt",
           "msoffcrypto-tool -p PASSWORD in out")]),
    "oleid:flash": Guide("Embedded Flash", "Flash (SWF) objects were found in OLE streams.",
                         "Historic exploit vector.", "", [S("Inspect streams", "streams.list")]),
    "oleid:generic": Guide("oleid indicator", "oleid rated this indicator as risky.", "", "",
                           [S("Check the Office triage table", "tab:oleid")]),
    "office:dde": Guide(
        "DDE field",
        "A DDE/DDEAUTO field can launch a program when the document opens, without macros.",
        "Used in 2017-2019 campaigns: DDEAUTO c:\\windows\\system32\\cmd.exe \"/k powershell …\".",
        "Very rare in legitimate documents.",
        [S("Review the DDE fields", "objects.dde", "msodde sample.docx"),
         S("Record the command as an IOC", "report")]),
    "ole:macro_streams": Guide("Streams with VBA code", "oledump marked these streams M (macro code).", "", "",
                               [S("Open the stream decompressed", "streams.list", "oledump.py -s <n> -v sample.doc"),
                                S("Full analysis in the Macros tab", "tab:macros")]),
    "ole:native": Guide(
        "Embedded file (Ole10Native)",
        "An OLE package object containing a file: often an executable, script or LNK the user is "
        "lured into double-clicking.",
        "A classic dropper technique that needs no macros.", "",
        [S("Extract the objects", "objects.extract", "oleobj -d out sample.doc"),
         S("Or dump the stream with oledump", "streams.list", "oledump.py -s <n> -e sample.doc")]),
    "ole:objectpool": Guide("ObjectPool storage", "Embedded OLE objects are present.", "", "",
                            [S("Extract the objects", "objects.extract", "oleobj -d out sample.doc")]),
    "ooxml:template": Guide(
        "Remote template / object",
        "The document references an external template, OLE object or frame that Word fetches on open.",
        "Remote template injection: the payload isn't in the attachment at all, so scanners pass it.",
        "Corporate templates on internal file shares (\\\\server\\templates) can be legitimate.",
        [S("Open the Relationships list", "parts.rels", "zipdump.py -s <n> -d sample.docx"),
         S("Note the target URL/UNC path as an IOC and check whether it's reachable from your network", "report")]),
    "ooxml:unsafe_xml": Guide(
        "XML with DTD / entity declarations",
        "A package part declares a DTD or XML entities. Office documents never need them.",
        "Entity expansion ('billion laughs') and external entities attack the parsers of scanners and "
        "sandboxes. This app refuses to parse such parts.",
        "None known for Office files.",
        [S("Look at the part's raw text (it is shown, not parsed)", "tab:parts", "zipdump.py -s <n> -d sample.docx"),
         S("Treat the file as crafted, and review the other findings", "")]),
    "ooxml:budget": Guide(
        "Parts too large to inspect",
        "Some parts were skipped because they decompress to more than the app reads, or the package "
        "compresses far more than real documents do.",
        "Zip bombs and padding are used to make scanners give up or time out.",
        "Very large embedded media (video) can exceed the limits legitimately.",
        [S("See which parts were skipped (Note column)", "tab:parts"),
         S("List sizes and ratios with zipdump (Parts → All options)", "tab:parts", "zipdump.py -e sample.docx")]),
    "pdfid:plugin": Guide(
        "pdfid plugin result",
        "A pdfid plugin scored the file (0 to 1) and may suggest what to do next.",
        "Plugins sum up the keyword counts in one number, handy when sweeping many files.",
        "A high triage score only means risky keywords are present; forms and links trigger it too.",
        [S("See the plugin output", "tab:pdfid", "pdfid.py -p plugin_triage sample.pdf"),
         S("Follow the keyword findings' own investigation steps", "")]),
    "pdfid:plugin_error": Guide(
        "pdfid plugin failed",
        "pdfid couldn't start or run a plugin, and stopped there, so later plugins didn't run.",
        "", "Plugins in Didier Stevens' repository written for older pdfid versions fail like this.",
        [S("Untick that plugin (the app marks incompatible ones) and run pdfid again", "tab:pdfid")]),
    "tool:unrecognized_output": Guide(
        "Tool output not recognized",
        "Part of a tool's output didn't match what this app knows how to read: a line in an unknown "
        "format, or a keyword it has no rating for. The rest of that tool's results are shown as usual.",
        "If a newer tool version changed its output, this app may be missing some of what the tool found, "
        "so a low verdict for this file is less certain.",
        "A tool printed an extra warning or notice, which is harmless.",
        [S("Read the tool's raw output for what it found", "tab:{tab}"),
         S("Check which version is installed (Help → Tool status)", "tool.status"),
         S("Run the logged command in a terminal to compare with what the app shows", ""),
         S("If a tool update caused it, use the previous version until the app is updated (standard "
           "edition: setup_vendor.py --ref <commit>; REMnux edition: a VM snapshot from before the update)",
           "", "python setup_vendor.py --ref <previous commit>")]),
    "router:identify_failed": Guide(
        "File structure could not be parsed",
        "Identifying the file's structure crashed or timed out, so the type was decided from byte signatures.",
        "Malformed containers are crafted to crash or hang parsers.",
        "Damaged downloads or truncated attachments.",
        [S("Check the leading bytes", "hex:0"), S("Review what the other tools report", "")]),
    "ooxml:external": Guide("External link", "An external relationship (usually a hyperlink).", "",
                            "Hyperlinks are normal.", [S("Review relationships", "parts.rels")]),
    "ooxml:exe": Guide("Executable inside the package", "A Windows PE file is stored as a document part.",
                       "Dropper payload carried inside the document.", "",
                       [S("Select the part and analyze it as a new sample", "parts.select:{name}")]),
    "obj:embedded": Guide(
        "Extracted embedded object",
        "An object was extracted from the document and saved with a .bin suffix.",
        "Executables, scripts, LNK files and nested documents are typical droppers.",
        "Images and Excel charts embedded in Word are normal.",
        [S("Analyze it as a new sample (double-click it in Objects & links)", "objects.list"),
         S("Get its SHA256 from the table and check it against your EDR / threat intel", "objects.list")]),
    "obj:external": Guide("External link from oleobj", "oleobj found an external relationship.",
                          "Possible remote template / OLE link.", "", [S("Review relationships", "parts.rels")]),
    "meta:dates": Guide("Timestamp anomaly", "Modified date is earlier than the created date.",
                        "Builder scripts and tampering produce impossible timestamps.",
                        "Copying files between systems with clock differences.",
                        [S("Review metadata", "tab:metadata", "olemeta sample.doc")]),
    "meta:author": Guide("Author information", "Author and last-saved-by from document metadata.",
                         "Reused author names link documents from the same campaign.", "",
                         [S("Review metadata", "tab:metadata", "olemeta sample.doc")]),

    # ----------------------------------------------------------------------- file level
    "router:header_offset": Guide(
        "Data before the header", "The file doesn't start with its format's magic bytes.",
        "Polyglots and evasion: some scanners only check offset 0.", "",
        [S("Look at the leading bytes", "hex:0")]),
    "router:polyglot": Guide("Polyglot file", "The file is valid as more than one format.",
                             "Each program opens a different interpretation; used to evade scanning.", "",
                             [S("Inspect the second header", "hex:{offset}")]),
    "router:mismatch": Guide(
        "Extension doesn't match content",
        "The file's real type differs from its extension (e.g. RTF named .doc).",
        "Office opens by content, so an RTF exploit can be mailed as 'invoice.doc' to slip past filters.",
        "Occasionally misnamed exports.", [S("Analysis already uses the real type; review the other findings", "")]),
    "router:encrypted_office": Guide("Password-protected Office file", "The document is encrypted.",
                                     "Hides macros from scanners.", "",
                                     [S("Decrypt it", "macros.decrypt")]),
    "router:late_pdf": Guide("Embedded PDF marker", "A %PDF marker exists deep inside the file.", "", "",
                             [S("Look at it in hex", "hex:{offset}")]),
}


def guide_key(f: Finding) -> str:
    """The knowledge-base key a finding carries (ref["kb"])."""
    return str(f.ref.get("kb") or "")


def guidance_for(f: Finding) -> Guide:
    """The guide for a finding, falling back to a generic one for its tool or tab."""
    key = guide_key(f)
    g = GUIDES.get(key)
    if g is None and key.startswith("pdf:"):
        g = GUIDES.get("pdf:peepdf_element")
    if g is None and key.startswith("oleid:"):
        g = GUIDES["oleid:generic"]
    if g is None:
        tab = f.ref.get("tab")
        return Guide(f.title, f.detail or "See the detail text.", "", "",
                     [S("Open the tool that produced this finding", f"tab:{tab or f.source}")])
    return g


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def fill(text: str, f: Finding) -> str:
    """Fill {keyword}/{object}/{payload}/{offset}/{name} from the finding."""
    def rep(m: re.Match) -> str:
        v = f.ref.get(m.group(1))
        return str(v) if v is not None else m.group(0)
    return _PLACEHOLDER.sub(rep, text)


def steps_for(f: Finding) -> list[Step]:
    """A finding's next steps with placeholders filled; steps that can't be filled become manual."""
    out = []
    for s in guidance_for(f).steps:
        action = fill(s.action, f)
        if _PLACEHOLDER.search(action):      # unfilled placeholder: make it a manual step
            action = ""
        out.append(Step(fill(s.label, f), action, fill(s.cli, f)))
    return out
