#!/usr/bin/perl -w 

use strict;
use warnings;
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha384 sha512 sha512_hex sha512_base64 sha256 sha256_hex sha256_base64 hmac_sha256 hmac_sha256_base64 hmac_sha256_hex hmac_sha512 hmac_sha512_base64);
use MIME::Base64;
use Crypt::CBC qw(random_bytes);
use Compress::Zlib;
use Crypt::OpenSSL::RSA;
use RPC::XML qw(:types);
use RPC::XML::Client;
use Data::Dumper;
use Encode;
#use Net::SSLGlue::LWP;   #try this voodoo if u r getting buttpain establishing https connections for your personalized feeds or upgrade to libwww-perl 6.05-2 and liblwp-protocol-https-perl 6.04-2 (that would be a better solution indeed, enabling this will bring issues when trying to connect to Twitter API)
use LWP::UserAgent;
use LWP::Protocol::https;
use LWP::Protocol::socks;
use JSON;
use FindBin; 
use Net::Twitter::Lite::WithAPIv1_1;
use XML::FeedPP;
use POSIX;


    
#	   LICENSE
#	   -------
    
	  ##############################################
	  ##             LulzSec License              ##
	  ##                                          ##
	  ## Do whatever you fucking want with this,  ##
	  ## but you must produce at least one act of ##
	  ## civil disobedience against the System    ##
	  ## and its rules, even if that represents   ##
	  ## not honoring this license at all.        ##
	  ## Fuck Cops' daughters, send cigarettes    ##
	  ## to those of us who are jailed, smash     ##
	  ## down CCTV cameras and...                 ##
	  ## also cocks, because lulz.                ##
	  ##                                          ##
	  ##############################################





my $pid;
my $AirchatPort = '8080';
#my $mustListenAllInterfaces = "nones";
my $mustListenAllInterfaces = "yeah";


my $fldigi_xmlrpc_server_url = 'http://localhost:7362/RPC2';

my $macroTX = 11;

my $currentmodem = 'PSK500R';
my $frequencycarrier = '1500';

my $mustEncrypt = "nones";
my $passphrase = 'x3UstrV@Hl;Mm#G9#_q,suckXZ$O^;55jlT*'; #default, cause it should have one at least, pl0x change this.

my $mustUseCallSign = "nones";
my $callsign;


my $mustNewsBroadcast = "nones";
my @rssfeeds = ("http://www.nytimes.com/services/xml/rss/nyt/HomePage.xml", "http://www.guardian.co.uk/rssfeed/0,,1,00.xml", "http://newsrss.bbc.co.uk/rss/newsonline_world_edition/front_page/rss.xml", "http://www.npr.org/rss/rss.php?id=2", "http://www.huffingtonpost.com/thenewswire/full_rss.rdf", "http://www.nytimes.com/services/xml/rss/nyt/International.xml", "http://www.washingtonpost.com/wp-dyn/rss/world/index.xml", "http://www.npr.org/rss/rss.php?id=1004", "http://wired.com/rss/index.xml");

my $mustCommunityBroadcast = "nones";
my @communityfeeds;

my $mustTweetOthers = "nones";
my $mustTweetBroadcast ="nones";


my $twitterhashtag2follow = "#anonymous";
my $searchtwtterm;

######## @2airchat twitter account ###
my $consumer_key_default="rH0XHij4BOdc5DmFFRbTw";
my $consumer_secret_default="GIyl3vPtSr0t9JLVSuE8HIVj5I3HNXClCoUa7cdNqQ";
my $access_token_default="2386106611-hLQTnLQpvnnsuiV0aZB2HvAC2fVRqUUEc1dvP5n";
my $access_token_secret_default="td6RSOUPMjVUc74LTjUIOsPgQqIrzAk5ZQjsXDPh7ZRK8";


my $consumer_key="rH0XHij4BOdc5DmFFRbTw";
my $consumer_secret="GIyl3vPtSr0t9JLVSuE8HIVj5I3HNXClCoUa7cdNqQ";
my $access_token="2386106611-hLQTnLQpvnnsuiV0aZB2HvAC2fVRqUUEc1dvP5n";
my $access_token_secret="td6RSOUPMjVUc74LTjUIOsPgQqIrzAk5ZQjsXDPh7ZRK8";


my $mustUseProxy = "nones";

my $torproxyhost = "127.0.0.1";
my $torproxyport = "9050";

my $proxyhost = "127.0.0.1";
my $proxyport = "8118";
my $proxyuser;
my $proxypass;

my $settings;

my @messagessent;
my @askedresend;
my @answeredresend;
my @alreadyasked;

my @newmessages;

my $currentmessages;
my $currentlogtxt;

my @donedecodedmsgs;

my $twitterResults;

my $checknews = "nones";
my $checkcommunity = "nones";
my $checktwitter = "nones";


my $mustAsk2resend = "nones";
my $mustAnswerResendreq = "nones";

my $cryptidx = '000000';

my $buildRoutes = 'yeah';

my $lastcheck = 0;
my $lastcheckrsnd = 0;

my $foolder = $FindBin::Bin;

my $MollyCrabappleShouldGetOnJabber = 'yes';

my (%dahfuckingkeys);

my (%rtable);

## ^ some stuff there probably should be deleted if not used anymore on the release

umask(077);

my (%awesomessages);

sub save_settings {
	
	$settings->{'settings'}{'Airchat Server'}{'fldigi_xmlrpc_server_url'} = $fldigi_xmlrpc_server_url ;
	$settings->{'settings'}{'Airchat Server'}{'AirchatPort'} = $AirchatPort ;
	$settings->{'settings'}{'Airchat Server'}{'mustListenAllInterfaces'} = $mustListenAllInterfaces ;
	$settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'} = $mustAsk2resend ;
	$settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'} = $mustAnswerResendreq ;
	$settings->{'settings'}{'Modem Settings'}{'currentmodem'} = $currentmodem ;
	$settings->{'settings'}{'Modem Settings'}{'frequencycarrier'} = $frequencycarrier ;
	$settings->{'settings'}{'Modem Settings'}{'mustEncrypt'} = $mustEncrypt ;
	$settings->{'settings'}{'Modem Settings'}{'passphrase'} = $passphrase ; #default, change this 
    $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'} = $mustUseCallSign ;
    $settings->{'settings'}{'Modem Settings'}{'callsign'} = $callsign ;
	$settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'} = $mustNewsBroadcast;
	$settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'} = $mustCommunityBroadcast ;
	$settings->{'settings'}{'Feeds'}{'rssfeeds'} = join("   ", @rssfeeds) ;
	$settings->{'settings'}{'Feeds'}{'communityfeeds'} = join("   ", @communityfeeds) ;
	$settings->{'settings'}{'Twitter'}{'mustTweetOthers'} = $mustTweetOthers ;
	$settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'} = $mustTweetBroadcast ;
	$settings->{'settings'}{'Twitter'}{'consumer_key'} = $consumer_key ;
	$settings->{'settings'}{'Twitter'}{'consumer_secret'} = $consumer_secret ;
	$settings->{'settings'}{'Twitter'}{'access_token'} = $access_token ;
	$settings->{'settings'}{'Twitter'}{'access_token_secret'} = $access_token_secret ; 
	$settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'} = $mustUseProxy ;
	$settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'} = $torproxyhost ;
	$settings->{'settings'}{'Tor and Proxy'}{'torproxyport'} = $torproxyport ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyhost'} = $proxyhost ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyport'} = $proxyport ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyuser'} = $proxyuser ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxypass'} = $proxypass ;
	$settings->{'settings'}{'penis'}{'penis'} = 'also cocks' ;
	
	
	  open( F, '>', "$foolder/.AirChatsettings");
	     print F JSON->new->utf8->pretty(1)->encode($settings);
	   close(F);

}



sub load_settings {
	print $FindBin::Bin;
	my $configfile;
	
	
	if ( -e "$foolder/.AirChatsettings" ) {
		                open(F, '<', "$foolder/.AirChatsettings") or die "cannot open file settings";
		              {
		                 local $/;
		                  $configfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    $settings = $json->allow_nonref->utf8->relaxed->decode($configfile);
    
   
    
 $fldigi_xmlrpc_server_url = $settings->{'settings'}{'Airchat Server'}{'fldigi_xmlrpc_server_url'}  if defined  $settings->{'settings'}{'Airchat Server'}{'fldigi_xmlrpc_server_url'}  ;
 $AirchatPort = $settings->{'settings'}{'Airchat Server'}{'AirchatPort'} if defined $settings->{'settings'}{'Airchat Server'}{'AirchatPort'} ;
 $mustListenAllInterfaces = $settings->{'settings'}{'Airchat Server'}{'mustListenAllInterfaces'}  if defined  $settings->{'settings'}{'Airchat Server'}{'mustListenAllInterfaces'}  ;
 $mustAsk2resend = $settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'}  ;
 $mustAnswerResendreq = $settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'}  ;
 $currentmodem = $settings->{'settings'}{'Modem Settings'}{'currentmodem'}  if defined  $settings->{'settings'}{'Modem Settings'}{'currentmodem'}  ;
 $frequencycarrier = $settings->{'settings'}{'Modem Settings'}{'frequencycarrier'}  if defined  $settings->{'settings'}{'Modem Settings'}{'frequencycarrier'}  ;
 $mustEncrypt = $settings->{'settings'}{'Modem Settings'}{'mustEncrypt'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustEncrypt'}  ;
 $passphrase  = $settings->{'settings'}{'Modem Settings'}{'passphrase'}  if defined  $settings->{'settings'}{'Modem Settings'}{'passphrase'}  ;
 $mustUseCallSign = $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'}  ;
 $callsign  = $settings->{'settings'}{'Modem Settings'}{'callsign'}  if defined  $settings->{'settings'}{'Modem Settings'}{'callsign'}  ;
 $mustNewsBroadcast = $settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'}  if defined  $settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'}  ;
 $mustCommunityBroadcast = $settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'}  if defined  $settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'}  ;
 @rssfeeds = split("   ", $settings->{'settings'}{'Feeds'}{'rssfeeds'})  if defined  $settings->{'settings'}{'Feeds'}{'rssfeeds'}  ;
 @communityfeeds = split("   ", $settings->{'settings'}{'Feeds'}{'communityfeeds'})  if defined  $settings->{'settings'}{'Feeds'}{'communityfeeds'}  ;
 $mustTweetOthers = $settings->{'settings'}{'Twitter'}{'mustTweetOthers'}  if defined  $settings->{'settings'}{'Twitter'}{'mustTweetOthers'}  ;
 $mustTweetBroadcast = $settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'}  if defined  $settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'}  ;
 $consumer_key = $settings->{'settings'}{'Twitter'}{'consumer_key'}  if defined  $settings->{'settings'}{'Twitter'}{'consumer_key'}  ;
 $consumer_secret = $settings->{'settings'}{'Twitter'}{'consumer_secret'}  if defined  $settings->{'settings'}{'Twitter'}{'consumer_secret'}  ;
 $access_token = $settings->{'settings'}{'Twitter'}{'access_token'}  if defined  $settings->{'settings'}{'Twitter'}{'access_token'}  ;
 $access_token_secret  = $settings->{'settings'}{'Twitter'}{'access_token_secret'}  if defined  $settings->{'settings'}{'Twitter'}{'access_token_secret'}  ;
 $mustUseProxy = $settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'}  ;
 $torproxyhost = $settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'}  ;
 $torproxyport = $settings->{'settings'}{'Tor and Proxy'}{'torproxyport'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'torproxyport'}  ;
 $proxyhost = $settings->{'settings'}{'Tor and Proxy'}{'proxyhost'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyhost'}  ;
 $proxyport = $settings->{'settings'}{'Tor and Proxy'}{'proxyport'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyport'}  ;
 $proxyuser = $settings->{'settings'}{'Tor and Proxy'}{'proxyuser'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyuser'}  ;
 $proxypass = $settings->{'settings'}{'Tor and Proxy'}{'proxypass'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxypass'}  ;


     }else{
		 save_settings();
	 }
}

load_settings();

sub save_messages {
	
	my $sv = \%awesomessages;
	  open( F, '>', "$foolder/.AirChatLog.json");
	     print F JSON->new->utf8->encode($sv);
	   close(F);

}

sub load_messages {
	
    my $msgfile;
	
	
	if ( -e "$foolder/.AirChatLog.json" ) {
		                open(F, '<', "$foolder/.AirChatLog.json") or die "cannot open file messages";
		              {
		                 local $/;
		                  $msgfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    my $getem = $json->allow_nonref->utf8->relaxed->decode($msgfile);
    
    %awesomessages = %{$getem};
    
  }
}

load_messages();


sub save_keys {
	
	my $sv = \%dahfuckingkeys;
	  open( F, '>', "$foolder/.AirChatkeys");
	     print F JSON->new->utf8->encode($sv);
	   close(F);

}

sub load_keys {
	
    my $keysfile;
	
	
	if ( -e "$foolder/.AirChatkeys" ) {
		                open(F, '<', "$foolder/.AirChatkeys") or die "cannot open file keys";
		              {
		                 local $/;
		                  $keysfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    my $getem = $json->allow_nonref->utf8->relaxed->decode($keysfile);
    
    %dahfuckingkeys = %{$getem};
    
  }else{
	  
	  
	  my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
	  
	  my $keyidx = $rsa->get_public_key_string() if defined $rsa;

	    $keyidx = sha512_hex($keyidx,"");
	    $keyidx = substr($keyidx,0,6);	 
	     
	  $dahfuckingkeys{$keyidx}{'pubK'}  = $rsa->get_public_key_string();
	  $dahfuckingkeys{$keyidx}{'privK'} = $rsa->get_private_key_string();
      $dahfuckingkeys{$keyidx}{'Local'} = 1;
      
      save_keys();
  }
}

load_keys();


sub create_another_localkey {
	
	
	  my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
	  
	  my $keyidx = $rsa->get_public_key_string() if defined $rsa;
	
	    $keyidx = sha512_hex($keyidx,"");
	    $keyidx = substr($keyidx,0,6);	 
	     
	  $dahfuckingkeys{$keyidx}{'pubK'}  = $rsa->get_public_key_string();
	  $dahfuckingkeys{$keyidx}{'privK'} = $rsa->get_private_key_string();
      $dahfuckingkeys{$keyidx}{'Local'} = 1;
      
      save_keys();
      
}



################################################################

sub twitter_load_tokens {


  $ENV{HTTPS_PROXY} = 'socks://127.0.0.1:9050';
    my $usetheshit = 0;
    
    if ($mustUseProxy eq "useProxy" ) {
	
	my $proxy = $proxyhost . ":" . $proxyport;
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
	$ENV{HTTPS_PROXY}               = "$proxy";
	$ENV{HTTP_PROXY}                = "$proxy";
    #$ENV{CGI_HTTP_PROXY}            = "$proxy";
    #$ENV{CGI_HTTPS_PROXY}           = "$proxy";
	
	if ($proxyuser && length($proxyuser) > 2 ) { 
	$ENV{HTTPS_PROXY_USERNAME}      = "$proxyuser";
	$ENV{HTTP_PROXY_USERNAME}       = "$proxyuser"; 
    }
	if ( $proxypass && length($proxypass) > 2) {
	$ENV{HTTP_PROXY_PASSWORD}       = "$proxypass"; 
    $ENV{HTTPS_PROXY_PASSWORD}      = "$proxypass";  
     }
     $usetheshit = 1;
	}
	
     if ($mustUseProxy eq "useTor" ) {

		 my $torproxy = 'socks://' . $torproxyhost . ':' . $torproxyport;     # Tor proxy
	$ENV{HTTPS_PROXY}              = "$torproxy";
	$ENV{HTTP_PROXY}               = "$torproxy"; 
	#$ENV{CGI_HTTP_PROXY}           = "$torproxy";
	#$ENV{CGI_HTTPS_PROXY}          = "$torproxy";
	$usetheshit = 1;
      } 
  
  my $nt = Net::Twitter::Lite::WithAPIv1_1->new(
    consumer_key    => $consumer_key,
    consumer_secret => $consumer_secret,
    useragent => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36',
    clientname => 'Air',
    clientver => '1.1',
    clienturl => 'https://github.com/lulzlabs',
    source => 'cock',
      
    useragent_args => {'env_proxy' => $usetheshit,},
    
    ssl => 1,
  );
  $nt->access_token($access_token);
  $nt->access_token_secret($access_token_secret);

  return $nt;
  
}

sub twitter_searching {

   my $searchkeyword = join("", @_);
   
    my $nt = twitter_load_tokens();
    
    if (!$searchkeyword) {
      $searchkeyword = $twitterhashtag2follow ;
    }

    if (length("$searchkeyword") < 2 ) {
       $searchkeyword = $twitterhashtag2follow ;
    }



   my $r =();
    eval {$r = $nt->search("$searchkeyword", { count => 10 })};
     if ( $@ ) {
                print "twtter: hey! :( search failed cause: $@\n";
            }else {
				
			}

    my @results = ();
    
    #$twitterResults = Dumper($r->{statuses});  #lelelele


    for my $tweet ( @{$r->{statuses}} ) { 

       my @item = ();

            @item = ( encode_utf8($tweet->{user}{screen_name}) , encode_utf8($tweet->{user}{name}) ,
                encode_utf8($tweet->{text}));

        push @results, \@item;
    }
    my @result;
    foreach (@results) {
       
       my @array=$_;
       my $name=$array[0][0];
       my $scrname=$array[0][1];
       my $text=$array[0][2];
 
        my $twit= "@" . "$name ($scrname):\n $text";
        chomp($twit);
        push @result, $twit;

   }
    

        my $retrn = join("\n\n-----\n\n",@result);
        
      return($retrn);  

}

sub twitter_check_mentions {

    my $nt = twitter_load_tokens();

    my $replies = $nt->mentions();
    my @results = ();
    my $twit;
    for my $tweet ( @$replies ) {
        my @item = ();
        if ( $tweet->{retweeted_status} ) {
            @item = ( encode_utf8($tweet->{user}{screen_name}) ,
                encode_utf8($tweet->{retweeted_status}{text}) ,
                encode_utf8($tweet->{retweeted_status}{created_at}));
        } else {
            @item = ( encode_utf8($tweet->{user}{screen_name}) ,
                encode_utf8($tweet->{text}) ,
                encode_utf8($tweet->{created_at}));
        }
        push @results, \@item;
    }
    my @result;
    foreach (@results) {
        
        my @array=$_;
        my $name=$array[0][0];
        my $text=$array[0][1];
        my $date=$array[0][2];

      
        $twit= "$name :  $text  - $date";
        chomp($twit);
        push @result, $twit;
 
   }
  
   my $retrn = join("\n\n",@result);
      
      return($retrn);  

}

sub twitter_msg {
  
  


  if (@_) {
    my $msg = join("", @_);
    
    my $nt = twitter_load_tokens();
    
    if (length("$msg") >= 140) {
		$msg = substr($msg,0,140);
	}
    
			my $tweet;
            eval { $tweet = $nt->update("$msg") };          
            if ( $@ ) {
                 print "twtter: hey! :( update failed because: $@\n";
               
            }else{
		      my $twttuser = encode_utf8($tweet->{user}{screen_name});
		      my $statusid = encode_utf8($tweet->{id_str});
		      my $returntweetlink = 'https://twitter.com/' . $twttuser . '/status/' . $statusid ;
              return($returntweetlink);     #for privacy related reasons we are not sure if we will use this returned link, if you want so just do it
            }

  }

}

#####################################################################

sub announce_list {
	

	my @contactstopost;
    my @announcestopost;
	foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( $dahfuckingkeys{$publickey}{'Local'} ) {
		  
		    my $cidx = $publickey;
            push(@announcestopost,$cidx);
  
	   }
		  
	  }
	
	
	
	foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalk'} ) {
		  
		    my $kidx = $contacted;
           push(@contactstopost,$kidx) if defined $kidx;
	   }
		  
	  }
	
	my $postallcontacts = join(":",@contactstopost);
	
	my @stufftodispatch;
	if (@announcestopost) {
	foreach my $announce (@announcestopost) {
		my $heyholetsgo;
		if ( @contactstopost ) {
		$heyholetsgo = "HOTEL-INDIA [ANNOUNCE:" . $announce . ":CTALK2:" . $postallcontacts . "]##END##";

	    }else{
	    $heyholetsgo = "HOTEL-INDIA [ANNOUNCE:" . $announce . "]##END##";

		}
		push(@stufftodispatch,$heyholetsgo);
	}
   
   my $postall = join("   ",@stufftodispatch);
   return $postall if defined $postall;
   }
}


sub receive_announce {
	  
	  
	  if (@_) {
	   my $pack = join("",@_);
	   if ($pack) {
	   my @sendhelloback;
	   my @sortedshit = split("##END##",$pack);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[ANNOUNCE:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my @kxcode = split("ANNOUNCE:",$sortedshit[$i],2);
				my $kidx = substr($kxcode[1],0,6);
				
				if (!$dahfuckingkeys{$kidx}{'Local'}) {
	            push(@sendhelloback,$kidx) if defined $kidx;
			    $rtable{$kidx}{'canListen'} = 1 if $kidx;
				
				if ($kxcode[1] =~ m/:CTALK2:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				$kxcode[1] =~ s/\](.*)$/ / ;
				my @crackpart = split(":CTALK2:",$kxcode[1]);
				my @extcodes = split(":",$crackpart[1]);
				
				foreach my $codx (@extcodes) {
			    if ( $codx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my $cidx = substr($codx,0,6);
				if (!$dahfuckingkeys{$cidx}{'Local'} || !$rtable{$cidx}{'canTalk'}) {
				$rtable{$cidx}{'canTalkExtended'} = 1 if defined $cidx;
				$rtable{$cidx}{'via'} = $kidx;
			     }
				
			     }
                 
                 }
			
                }
                
			  }

         }
       }
      
    my $posthiback;      
    if (@sendhelloback)   {
	my @hiback;
	 my $postitall;
    $postitall = join(":",@sendhelloback);
    
    foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( $dahfuckingkeys{$publickey}{'Local'} ) {
		  
		    my $codx = $publickey;
		    my $postgreetz = "HOTEL-INDIA [OHAITHERE:" . $postitall . ":" . "][HEREIZ:$codx]##END##";  ## adding some padding
            push(@hiback,$postgreetz);
            
	   }
		  
	  }
	$posthiback = join("  ",@hiback);
    }
	return $posthiback if defined $posthiback;
   }
	
 }
}


sub build_list {
	
     if (@_) {
	   my $pack = join("",@_);
   
	   if ($pack) {
	   my @sortedshit = split("##END##",$pack);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[OHAITHERE:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				
				my @kxcodes = split("OHAITHERE:",$sortedshit[$i],2);
				
				if ($sortedshit[$i] =~ m/\[HEREIZ:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) { 

				my @gethelloer = split("HEREIZ:",$kxcodes[1]);
				my $reachedidx = substr($gethelloer[1],0,6);
				$kxcodes[1] =~ s/\](.*)$/ / ;
				my @lotidx = split(":",$kxcodes[1]);
				
				foreach my $kidx (@lotidx) {
			    if ( $kidx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my $kidx = substr($kidx,0,6);
				
				if ( $dahfuckingkeys{$kidx}{'Local'} ) {
				$rtable{$reachedidx}{'canTalk'} = 1 if defined $kidx;
				delete $rtable{$reachedidx}{'canTalkExtended'} if defined $kidx;
			     }
				
			     }
               }
		   }
         }
       }
       
   }
   
  }
}


###################################################################

sub asymm_encrypt {
	
	if (@_) {
		
	my ($keycode, $txpack) = @_;
	

	    my $dahpassiez;
		$dahpassiez = Crypt::CBC->random_bytes('4096');
	    $dahpassiez = sha256_base64($dahpassiez,"");	
	
	if ( $dahfuckingkeys{$keycode} && $dahfuckingkeys{$keycode}{'pubK'} ) {
		
		my $pubKstring = $dahfuckingkeys{$keycode}{'pubK'} ;
		my $public_rsa = Crypt::OpenSSL::RSA->new_public_key($pubKstring) || die "$!";
        
        my $cpassie = $public_rsa->encrypt($dahpassiez);
		my $ctx;
	  my $useThisk = '000000';
	  		            
	  		             if ( $dahpassiez) {	

						 	 foreach my $kidx ( keys %dahfuckingkeys) {
                                if ( $dahfuckingkeys{$kidx}{'Local'} ) {
				                   $useThisk = $kidx ;
			                     }
				             } 
							 
							 		
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $dahpassiez;

		             eval{$ctx = $cipher->encrypt($txpack)};
		             eval{$useThisk = $cipher->encrypt($useThisk)};
					             if ($@) {
						 print "error encrypting";
						
					 }else {

						 
						 $useThisk = encode_base64($useThisk,"");
						 $cpassie = encode_base64($cpassie,"");
						 $ctx = encode_base64($ctx,"");
						 
						 my $readypack = $cpassie .'</Key>'. $useThisk . '</reply>' . $ctx ;
						 return ($readypack);
					 }	     
				     
				     }
	  
	  
	  
	  
	  }
	
	
   }


  
}



######


sub asymm_decrypt {
	
	if (@_) {
		
	my ($keycode, $ctpack) = @_;

	 if ($ctpack =~ m/\<\/Key\>/ ) {
                my $septr = '</Key>';
                my @letbreak = split($septr,$ctpack);

		my $ctpass = $letbreak[0];
		my $ctpx = $letbreak[1];
		
		
		my $septr2 = '</reply>';
        my @break2 = split($septr2,$letbreak[1]);
        my $ctreply2 = $break2[0] ;
        my $ctx =  $break2[1] ;

				
		$ctpass = decode_base64($ctpass);
		$ctx = decode_base64($ctx);
		$ctreply2 = decode_base64($ctreply2);  
		
   
		   
	if ( $dahfuckingkeys{$keycode} && $dahfuckingkeys{$keycode}{'privK'} ) {
		
		my $privKstring = $dahfuckingkeys{$keycode}{'privK'} ;
		my $private = Crypt::OpenSSL::RSA->new_private_key($privKstring) || die "$!";

        my $passie = $private->decrypt($ctpass);
		my $plaintext;
	  
	  		             if ( $passie) {			
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $passie;

		             eval{$plaintext = $cipher->decrypt($ctx)};
		             eval{$ctreply2  = $cipher->decrypt($ctreply2)};
					             if ($@) {
						 print "error decrypting";
					
					 }else {
                         if ( $ctreply2 eq '000000' ) {
			               $plaintext = "ORIGIN: ---- \n\n" . $plaintext ;
		                 }else{
						   $plaintext = "ORIGIN: " . $ctreply2 . "\n\n" . $plaintext ;
						 }
		                 
                         
                         if ( $dahfuckingkeys{$ctreply2}{'name'} ) {
							 $plaintext = "REPLY-TO: " . $dahfuckingkeys{$ctreply2}{'name'} . "\n" . $plaintext ;
							 
						 }
                         
						 return ($plaintext);
					 }	     
				     
				     }
	  
	  
	  
	  
	  }
	
	
   }

 }
	
}



####################################################################

sub check_for_commands {
	
	if (@_) {
	my $lovelymsg = join("",@_);
	
	my $markitlocal;
	
	if ($lovelymsg =~ m/^:/ ) {
		
		if ($lovelymsg =~ m/^:local/ ) {
		
		$lovelymsg =~ s/^:local// ;
		$markitlocal = "yeah";
	    }

						 if ($mustNewsBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:news?/) {
								  if ($markitlocal) {
								     my $newslines = fetch_rss(@rssfeeds);
								     $lovelymsg = $lovelymsg . "\n\n" . $newslines if defined $newslines;
							      }else{
									  $checknews = "yeah";
									 
									  }
							  }
						    }
						    if ($mustCommunityBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:sup?/) {
								  if ($markitlocal) {
								  	  my $feedlines = fetch_rss(@communityfeeds);
								     $lovelymsg = $lovelymsg . "\n\n" . $feedlines if defined $feedlines;
							      }else{
									  $checkcommunity = "yeah";
									  }
							  }
						    }
						 if ($mustTweetOthers eq "yeahcool") {
							  if ($lovelymsg =~ m/^:tweet /) {
								  my $totweet = $lovelymsg ;
								  $totweet =~ s/^:tweet //;
								  my $candy = twitter_msg($totweet);
								  if ($markitlocal) {
									  
								    $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{
									  
									  }
								  
								  
							  }
						    }
						    
						    if ($mustTweetBroadcast eq "yeahcool") {
							
							  if ($lovelymsg =~ m/^:twitter/ ) {
								  
								 
								  
								  
								  
								 if ($markitlocal) {
									# $candy = encode_utf8($candy);
									my  $candy = twitter_searching();
								     $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{
                                             # changed to just answer last request
                                             $searchtwtterm = undef;
                                            $checktwitter = "yeah";
									  }
								 
							  }
						    }
						    if ($mustTweetBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:searchtwitter=/) {
								  my @searchtweets = split("=", $lovelymsg, 3);
								  my @clnsearchtweets = split(" ",$searchtweets[1]);
								  
								  $searchtwtterm = $clnsearchtweets[0];
								  
								 if ($markitlocal) {
								
									my $candy = twitter_searching($searchtwtterm);
								    $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{ 
									  # changed to just answer last request
                                             $checktwitter = "yeah";
                                             
									  }
								  
								  
							  }
						    }

						 return($markitlocal,$lovelymsg);
	}
  }
}




sub sendingshits {
	
	
	
	
	if (@_) {
	
	my ($keyidx, $thestuff)	= @_;
	my $makeitlocal;
	my $lovelymsg = $thestuff;
	
	if ( $mustUseCallSign eq "yeah" && $callsign && length($callsign) > 2 ) {
	
	$lovelymsg = $lovelymsg . "\n\n----------\n\n" . "FROM CALLSIGN: " . $callsign . "\n" ; 	
		
	}
	
	my $hashin;
	
		my $ttmsgcode;
		$ttmsgcode = Crypt::CBC->random_bytes('128');
	    $ttmsgcode = sha512_hex($ttmsgcode,"");
	    $ttmsgcode=substr($ttmsgcode,0,6);
	
	if ($lovelymsg =~ m/^:/ ) {
		
		my ($isLocal,$chkdmessage) = check_for_commands($lovelymsg);
		
		return if $chkdmessage =~ m/^:trash/ ;
					 

                  if ($isLocal && $isLocal eq "yeah" ) {
					     $lovelymsg = $chkdmessage;
						 $hashin = substr(sha256_hex($lovelymsg),0,8);
						 $ttmsgcode = $ttmsgcode . "-" . $hashin;
						 $awesomessages{$ttmsgcode}{'hash'} = "$hashin";
						 $awesomessages{$ttmsgcode}{'content'} = decode_utf8($lovelymsg);
						 $awesomessages{$ttmsgcode}{'txrx'} = "tx"; 
						 $awesomessages{$ttmsgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$ttmsgcode}{'resentcount'} = 0;
						 $awesomessages{$ttmsgcode}{'isLocal'} = 1;
						 return;
					 }
						 
	}
	
	my $copyof = decode_utf8($lovelymsg);
	
	my $cryptc = '00';
	
	if ($keyidx ne '00' && $keyidx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
		
		if ( $dahfuckingkeys{$keyidx} && $dahfuckingkeys{$keyidx}{'pubK'} ) {
			
			my $encryptedpack = asymm_encrypt($keyidx,$lovelymsg);
			
			$lovelymsg = $encryptedpack if defined $encryptedpack;
			$cryptc = '03' if defined $encryptedpack;
			$cryptidx = $keyidx if defined $encryptedpack;
		}
		
	}else{
		$cryptidx = '000000';
	}
	
	$lovelymsg = compress($lovelymsg);
	
	
	if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {

		
	   my $cipher = Crypt::CBC->new(
		         {    
		           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
		
		          'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
		       #    'cipher'        => 'Camellia_PP',
		
		           'padding'       => 'standard',
		    
		        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
		         }
		        );
	
	
	$cipher->{'passphrase'} = $passphrase;
	$lovelymsg = $cipher->encrypt($lovelymsg);
	
	     if ( $cryptc eq '00' ) {
               $cryptc = '01';	
               $cryptidx = '000000';
            }else{
         if ( $cryptc eq '03' ) {
               $cryptc = '05';	
            } 
		}
    }
	
	$lovelymsg = encode_base64($lovelymsg,"");

	# "LIMA-UNIFORM-LIMA-ZULU" is the padding used in case you r using VOX function or so, and need to take care of the time needed to trigger it
	my $headerz = "LIMA-UNIFORM-LIMA-ZULU [BEGINCOMM]";
	$hashin = substr(sha256_hex($lovelymsg),0,8);
	my $pack = $headerz . $lovelymsg . "[cksum:$hashin:$ttmsgcode:$cryptc:$cryptidx][ENDCOMM]##END##";
	
	$ttmsgcode = $ttmsgcode . "-" . $hashin;

    my $msgarchive = $ttmsgcode . ":" . $pack;
    if (scalar(@messagessent) >= 15) {
		shift(@messagessent);
	}

    				     $awesomessages{$ttmsgcode}{'hash'} = "$hashin";
						 $awesomessages{$ttmsgcode}{'content'} = "$copyof";
						 $awesomessages{$ttmsgcode}{'pack'} = $pack;
						 $awesomessages{$ttmsgcode}{'txrx'} = "tx"; 
						 $awesomessages{$ttmsgcode}{'cryptc'} = $cryptc; 
						 if ( $cryptidx ne '000000' ) {
						 $awesomessages{$ttmsgcode}{'cryptidx'} = $cryptidx; 
					     }
						 $awesomessages{$ttmsgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$ttmsgcode}{'resentcount'} = 0;
    return ($pack);
  }
}


#########################
# check if resent

sub check_if_resent {
	
	if (@_) {
		   my $msgcode = join("",@_);
				if ($mustAsk2resend eq "yeahbaby") {
				
						if (@alreadyasked) {
							my $ifoundit;
							foreach (@alreadyasked) {
							   if ( $msgcode =~ m/$_/ ) {
						           $ifoundit = "yeah";
						       }else{

							   }
						     }
						     if ( !$ifoundit ) {
								   push(@askedresend,$msgcode);
								   push(@alreadyasked,$msgcode);
							   }
					      }else{
								   push(@askedresend,$msgcode); 
								   push(@alreadyasked,$msgcode);
							   
						  }
						  
						  
						  resenditpl0x();
					  }


   }
}


# decoding
##########################################

sub gettingdecodedmsg {
	
	    if (@_) {
	    my @tonOfShit;

		my $fullOfshit = join("",@_);
		$fullOfshit =~ s/\n//g ;
		my $headerz = "[BEGINCOMM]";
		my $hashin;
		my $wrapped = "nones";
		my $segment;
		
		my $doneAlready = "nones";
		
		my $msgcode;
		
		my $isEncrypted;
		
		@tonOfShit = split("##END##",$fullOfshit);

		for (my $i = 0 ; $i < scalar(@tonOfShit); $i++) {
		   
			
				if ($tonOfShit[$i] =~ m/\[BEGINCOMM\]/ ) {
				$wrapped = "yeah";
				$tonOfShit[$i] =~ s/^(.*)\[BEGINCOMM\]// ;
				$segment = "";
			     }
			

				if ($tonOfShit[$i] =~ m/\[ENDCOMM\]/ ) {
					
					if ($tonOfShit[$i] =~ m/\[cksum:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]/ )
				 {
					 

					 $doneAlready = "nones";

		             my @revhashin = split("cksum:", $tonOfShit[$i]);
		             my @prehashin = split(":",$revhashin[1]);
		             
		             $hashin = $prehashin[0];
		             
		             $msgcode = $prehashin[1] . "-" . $prehashin[0];
		             
		             my $cryptc = $prehashin[2];
		             my $locatekey = $prehashin[3];
		             $locatekey = substr($locatekey,0,6);
		             
		             

		          if (!$msgcode) {
					   
				   }else{
					if ( $wrapped eq "yeah") { 
		             
					if ( $hashin && $msgcode && !$awesomessages{$msgcode} ) {
					
					
					$wrapped = "nones";
					my $final = $tonOfShit[$i];
					$final =~ s/\[ENDCOMM\](.*)$// ;
					$final =~ s/\[cksum:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]// ;
					
					$segment = $segment . $final ;

					chomp($segment);
					my $probe = substr(sha256_hex($segment),0,8);

					if ($probe eq $hashin ) {

					if ( $segment =~ m/^U2FsdGVkX1/ ) {
						$isEncrypted = "yeah";
					}else{
						$isEncrypted = "nones";
					}
					
					
						$segment = decode_base64($segment);

		             if ( $isEncrypted eq "yeah" && ( $cryptc eq '01' || $cryptc eq '05' ) ) {			
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $passphrase;

		             eval{$segment = $cipher->decrypt($segment)};
					             if ($@) {
						 print "error decrypting";

					 }else {
						 
					 }	     
				     
				     }	     

						 eval{$segment = uncompress($segment)};
						if ($@) {
						 print "error uncompressing";

					    }else {
						 
					     if ( $cryptc eq '03' || $cryptc eq '05' ) {			
							   
							   my $asymmdec_text = asymm_decrypt($locatekey, $segment) if defined $segment;
							   if ( $asymmdec_text ) {
							     $segment = $asymmdec_text ;
						       }else{
								 $segment = undef ;  
							   }
							   
						   }						 
						 
						 if ($segment) {
						    
						    $segment = Encode::decode_utf8($segment);
						    $segment =~ s/^:local/local/ ;
						 my ($isLocal,$ckdmsg) = check_for_commands($segment);

						 push(@newmessages,$segment);
						 $awesomessages{$msgcode}{'hash'} = "$probe";
						 $awesomessages{$msgcode}{'content'} = "$segment";
						 $awesomessages{$msgcode}{'txrx'} = "rx"; 
						 $awesomessages{$msgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$msgcode}{'resentcount'} = 0;
						 $awesomessages{$msgcode}{'cryptc'} = $cryptc; 
						 if ($isLocal) {
							 $awesomessages{$msgcode}{'isLocal'} = 1;
						 }

						 push(@donedecodedmsgs,$msgcode);
					      }
					 }

					}else{
						
						check_if_resent($msgcode);
				  
					}
					
				  	
				   }
				   # here	
			      }else{ 
			        
			       
			       check_if_resent($msgcode);
			       
			       }
			   }
				   
				}	 
				
					if ($wrapped eq "yeah" ) {

				$segment = $segment . $tonOfShit[$i];

			}
	
		}
				
		}    
		    if ($mustAsk2resend eq "yeahbaby") {
			resenditpl0x();
		}
			return(@newmessages);
   }
}

##########################################
#check if someone is asking to resend a msg that was received corrupted on the other end

sub check_resend_requests {
	    
	    if (@_) {
	    my @loggedshit;
	    
	    my @newmsgs;
	    
	    my $alreadydone = "nones";

		@loggedshit = @_;
		chomp(@loggedshit);
		my $gathershit = join("",@loggedshit);

		my @sortedshit = split("##END##",$gathershit);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[PL0XRESNDMSG:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]/ ) {
				my @loocode = split("PL0XRESNDMSG:",$sortedshit[$i],2);
				my $msgcode = substr($loocode[1],0,15);

				
			if ($msgcode) {			
				
			 if ( $awesomessages{$msgcode} && $awesomessages{$msgcode}{'pack'} && $awesomessages{$msgcode}{'resentcount'} <= 1  ) {
					push(@newmsgs,$awesomessages{$msgcode}{'pack'});
					my $newcount = ($awesomessages{$msgcode}{'resentcount'} + 1);
					$awesomessages{$msgcode}{'resentcount'} = $newcount;
				}
				
				
			 }
			}
	}  ## youz taking drugz again 
	   if (@newmsgs) {
		    	my	 $txstatus = main::get_tx_status();
	                                          	 while ($txstatus =~ m/tx/) {
                                        			 sleep(10);
	                                         		 $txstatus = main::get_tx_status();
	                                              	 }

        gogogodispatch(join("  ",@newmsgs));
	}
	
  }
}



##########################################

our $client;

our $term;
our $OUT = \*STDOUT;
our $debug;

our %methods;
our %commands;
our %encoders;

our %opts;

our $isconnected;


%encoders = ( "b" => \&RPC_BOOLEAN, "6" => \&RPC_BASE64,
	      "d" => \&RPC_DOUBLE, "s" => \&RPC_STRING );
	     
%opts = ( "c" => "", "d" => 0, "u" => "http://localhost:7362/RPC2" );

# create client
$client = RPC::XML::Client->new($fldigi_xmlrpc_server_url);


sub modem_setting {
	
	if (@_) {	 
	my $r;
	my ($tryit, $setfreq) = @_;
	req("modem.set_by_name", $tryit);	
    req("modem.set_carrier", $setfreq);
	return unless defined($r = req("main.get_afc"));
	if ($r->value eq 1) 
	{
		req("main.toggle_afc");
	}
    return unless defined($r = req("main.get_lock"));
	if ($r->value eq 0) 
	{
		req("main.toggle_lock");
	}

	return "penis";
	
   }
}

sub resenditpl0x {
	
	    if (@askedresend && scalar(@askedresend) >= 1) {	
	my @req2resend;
	foreach(@askedresend) {	
		chomp;	
	    my $rsndit = "LIMA-UNIFORM-LIMA-ZULU [PL0XRESNDMSG:$_]##END##";
	    push(@req2resend,$rsndit);
     }
     my $askq = join("  ",@req2resend);

			my $txstatus = main::get_tx_status();
		 while ($txstatus =~ m/tx/) {
			 sleep(10);
			 $txstatus = main::get_tx_status();
		 }
		 

	gogogodispatch($askq);
	@askedresend = ();
	return "penis";	
    }
	
}

sub send_line
{
    if (@_) {
	req("text.clear_tx");	
	req("text.add_tx_bytes", join(" ", @_));
	return "penis";
    }
}

sub sendthefuckout 
{
	req("main.run_macro", $macroTX);
	return "penis";
}

sub get_line_tx_timing {
	
	if (@_) {
	my $r;
  
    return unless defined($r = req("main.get_tx_timing",join(" ", @_)));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    return($rctxt);
    }
}

sub get_tx_status {
	
    my $r;

    return unless defined($r = req("main.get_trx_status"));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    return($rctxt);
    
	
}


sub get_recv_text
{
    my ($r, $len);

    return unless defined($r = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", 0, $r->value));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}

sub get_recv_last
{
    my ($rone, $r, $len);

    return unless defined($rone = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", $lastcheck, $rone->value));
    $lastcheck = $rone->value;
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}

sub get_recv_last_rsndreq
{
    my ($rone, $r, $len);

    return unless defined($rone = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", $lastcheckrsnd, $rone->value));
    $lastcheckrsnd = $rone->value;
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}


sub encoderpc
{
    my $aref = $_[0];
    return unless (exists( $methods{$aref->[0]} ));

    my $sig = $methods{$aref->[0]}->[0]; $sig =~ s/.+://;
    my @args = split(//, $sig);

    # Try to find an encoder for each format string char.
    # Use it to encode the corresponding method argument.
    for (my $i = 0; $i <= $#args; $i++) {
	if (exists($encoders{$args[$i]}) && exists($aref->[$i])) {
	    print "Encoding arg " . ($i+1) . " as $args[$i]\n" if ($debug);
	    $aref->[$i+1] = &{ $encoders{$args[$i]} }($aref->[$i+1]);
	}
    }
}

sub req
{
    encoderpc(\@_);
    my $r = $client->send_request(@_);
    if (!ref($r)) {
	$r = undef;
	$isconnected = "nones";
    }
    elsif ($r->is_fault()) {
	print $OUT "Error " . $r->value->{"faultCode"} . ": " .
	           $r->value->{"faultString"} . "\n";
	$r = undef;
    $isconnected = "nones";	
    }else{
		$isconnected = "yeahbaby";
		}

    return $r;
}

sub decoderpc
{
    my $r;
    return "" unless defined($r = req(@_));
    return ref($r->value) ? Dumper($r->value) : $r->value;
}



sub build_cmds
{
    %methods = ();

    if (defined(my $r = req("fldigi.list"))) {
	foreach (@{$r->value}) {
	    $methods{ $_->{"name"} } = [ $_->{"signature"}, $_->{"help"} ];
	}

    }
}

# build commands hashes
build_cmds();

###########  sending to xmlrpc server

sub gogogodispatch {

  if (@_) {
	  
	my $r; 
	my $r2; 
    
	return unless defined($r = req("modem.get_name"));
	return unless defined($r2 = req("modem.get_carrier"));	
	if ($r->value ne "$currentmodem" || $r2->value ne "$frequencycarrier" ) 
	{
		
		modem_setting($currentmodem, $frequencycarrier);
	}

	  
           my $delivery = join("   ",@_);
           my $tadam = send_line($delivery) if defined $delivery;
           my $tutu = sendthefuckout() if defined $tadam;

           return ("Message Sent") if defined $tutu;

  }
}




###############################################################################

sub find_url {
   my $text = shift;
   if($text =~ /((ftp|http|https):\/\/[a-zA-Z0-9\/\\\:\?\%\.\,\&\;=#\-\_\!\+\~]*)/i){
	  return $1;
   }elsif($text =~ /(www\.[a-zA-Z0-9\/\\\:\?\%\.\,\&\;=#\-\_\!\+\~]*)/i){
	  return "http://".$1;
   }
   return undef;
}
 
sub fetch_rss {
	
	if (@_) {
		
		my @gofeeds = @_;

    my $ua = new LWP::UserAgent;
    $ua->agent("Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36");
    $ua->protocols_allowed( [ 'http','https'] );
    
    if ($mustUseProxy eq "useTor" ) {

    my $torproxy = 'socks://' . $torproxyhost . ':' . $torproxyport;
	$ENV{HTTPS_PROXY}              = "$torproxy"; 
	$ENV{HTTP_PROXY}               = "$torproxy";
    $ENV{CGI_HTTP_PROXY}           = "$torproxy";
	$ENV{CGI_HTTPS_PROXY}          = "$torproxy";
	$ua->env_proxy;
      } 
      
    if ($mustUseProxy eq "useProxy" ) {
	
	my $proxy = 'http://' . $proxyhost . ':' . $proxyport;
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
	$ENV{HTTPS_PROXY}               = "$proxy";
	$ENV{HTTP_PROXY}               = "$proxy";
	$ENV{CGI_HTTP_PROXY}            = "$proxy";
    $ENV{CGI_HTTPS_PROXY}           = "$proxy";
	
	if ($proxyuser && length($proxyuser) > 2 ) { 
	$ENV{HTTPS_PROXY_USERNAME}      = "$proxyuser";
	$ENV{HTTP_PROXY_USERNAME}      = "$proxyuser"; 
    }
	if ( $proxypass && length($proxypass) > 2) {
	$ENV{HTTP_PROXY_PASSWORD}      = "$proxypass"; 
    $ENV{HTTPS_PROXY_PASSWORD}      = "$proxypass";  
     }
     $ua->env_proxy;
	}
	
  
    
  my $got_url = $gofeeds[int rand($#gofeeds)];
  
  my $rss_url = find_url($got_url);
  
  
  return unless ($rss_url);

  my $request = HTTP::Request->new('GET', $rss_url);

  my $response = $ua->request ($request);
  
		 

  return unless ($response->is_success);
  

  my $source = $response->content;
    my $feed = XML::FeedPP->new( $source, -type => 'string');  

    my $wownews = "NEWS:\n\n";
    my $i = 0;
    foreach my $item ( $feed->get_item() ) {
        if ($i <= 6) {
         $wownews = $wownews . $item->title() . "\n\n";
        }
        $i++
    }

          return($wownews);
   }
}

###############################################################################
 my $rcved_msgs;
 my $txwarning;
 my $timercheckresend = 0;
 my $timernews = 0;
 my $timercommunity = 0;
 my $timertwitter = 0;
 
 my $timersavemsg = 0;
 
 my $timerRoutes = 0;
 
sub get_last_msgs {
   
     my $checkmsgs = main::get_recv_text();
     my $donusdone = main::gettingdecodedmsg($checkmsgs) if defined $checkmsgs;
     
     $currentlogtxt = "";
	 $currentlogtxt = $currentlogtxt . "Content-type: text/plain\n\n";
     $currentlogtxt = $currentlogtxt . "######################################################\n";
     $currentlogtxt = $currentlogtxt . "###    MESSAGES LOG on ";
	 my $logdate = POSIX::strftime "%a %b %e %H:%M:%S %Y    ###\n",localtime;
     $currentlogtxt = $currentlogtxt .  $logdate;  
     $currentlogtxt = $currentlogtxt . "######################################################";
     $currentlogtxt = $currentlogtxt . "\n\n================================================================"; 
		
	my $timenow = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
	$currentmessages = "";	
   foreach my $message (sort { $awesomessages{$b}{'timestamp'} <=> $awesomessages{$a}{'timestamp'} } keys %awesomessages) {

   
   if (int($timenow - $awesomessages{$message}{'timestamp'})  >= 3600 )
   {
	   $awesomessages{$message}{'pack'} = undef;
   }
   
   my $cryptlabel = ' ';
   my $sentto = "\n";
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '01' ) {
	   $cryptlabel = '  [Encrypted AES-256]';
   }
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '03' ) {
	   $cryptlabel = '  [Encrypted RSA-2048/AES-256]';
   }
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '05' ) {
	   $cryptlabel = '  [Encrypted AES-256] + [Encrypted RSA-2048/AES-256]';
   }
   if ($awesomessages{$message}{'cryptidx'} && $awesomessages{$message}{'cryptidx'} ne '000000' && length($awesomessages{$message}{'cryptidx'}) > 4 ) {
	   
	   my $idxc = $awesomessages{$message}{'cryptidx'} ;
	   if ( $dahfuckingkeys{$idxc}{'name'} && length($dahfuckingkeys{$idxc}{'name'}) >= 1 ) {
		   $sentto = "\nSENT-TO : " . $dahfuckingkeys{$idxc}{'name'} . "\n\n";
	   }
	  
   }
   
   my $datee = localtime($awesomessages{$message}{'timestamp'});
   my $messagecontent = main::encode_utf8($awesomessages{$message}{'content'});
   my $domb = "\n\nMESSAGE CODE: " . $message . $cryptlabel . "\n\n\n" . $sentto . $messagecontent . 
   "\n\n\n\n\n\n" . $datee ;
   my $edomb = HTML::Entities::encode_entities_numeric($domb, '<>&"');
  
   
   if ( $awesomessages{$message}{'isLocal'} ) {
	   $currentmessages = $currentmessages . "<div id='localmsg'><code><pre>\n\nLOCAL MESSAGE:$edomb</pre></code></div>";
	   $currentlogtxt = $currentlogtxt . "\n\nLOCAL MESSAGE:$domb";
   }else{
   
   if ($awesomessages{$message}{'txrx'} eq "tx") {
	       $currentmessages = $currentmessages . "<div id='sent'><code><pre>$edomb - Sent</pre></code></div>";
	       $currentlogtxt = $currentlogtxt . "$domb - Sent";
	   }else{
            $currentmessages = $currentmessages . "<div id='received'><code><pre>$edomb - Received</pre></code></div>";
            $currentlogtxt = $currentlogtxt . "$domb - Received";
     }
 }
     $currentmessages = $currentmessages . "----------------------------------------------------------------";
     $currentlogtxt = $currentlogtxt . "\n\n----------------------------------------------------------------";
    }	
			    
		return;
		
}

sub refresh_last_msgs {
	
	
			 if ( ($txwarning && $txwarning =~ m/fldigi is not running currently/i ) || !%methods ) {


			 	 main::build_cmds();
	             main::modem_setting($currentmodem, $frequencycarrier) if %methods;
		 }
		
	eval{$rcved_msgs = get_last_msgs()};
	
		if ($mustAnswerResendreq eq "yeahbaby") {
		 if ($timercheckresend > 4) {
			 my $pack;
     	     $pack = main::get_recv_last_rsndreq();
			 main::check_resend_requests($pack) if defined $pack;
			 $timercheckresend = 0;
			 }
		$timercheckresend++;	
	} 
	
	   if ($mustNewsBroadcast eq "yeahcool") {
		 if ($timernews >= 1) {
	     if ($checknews eq "yeah") {
			my $feedresults = main::fetch_rss(@rssfeeds);
			 my $postnews = main::sendingshits('00',$feedresults) if defined $feedresults;
		     my $mega = main::gogogodispatch($postnews) if defined $postnews;
			 $checknews = "nones";
			 $timernews = 0;
		 }
	    }
	    $timernews++;
       } 
       
       if ($mustCommunityBroadcast eq "yeahcool") {
		 if ($timercommunity >= 1) {
	     if ($checkcommunity eq "yeah") {
			 my $feedresults = main::fetch_rss(@communityfeeds);
			 my $postnews = main::sendingshits('00',$feedresults) if defined $feedresults;
		     my $mega = main::gogogodispatch($postnews) if defined $postnews;
			 $checkcommunity = "nones";
			 $timercommunity = 0;
		 }
	    }
	    $timercommunity++;
       } 

       if ($mustTweetBroadcast eq "yeahcool") {
		 if ($timertwitter >= 1) {
	     if ($checktwitter eq "yeah") {	
			 my $twtresults;
			 if ( $searchtwtterm ) {
				  $twtresults = main::twitter_searching($searchtwtterm);
				  $twtresults =~ s/^:/_/ ;
			  }else{
				   $twtresults = main::twitter_searching();
				   $twtresults =~ s/^:/_/ ;
			   }	     
			 my $posttweets = main::sendingshits('00',$twtresults) if defined $twtresults;
		     my $mega = main::gogogodispatch($posttweets) if defined $posttweets;
			 $checktwitter = "nones";
			 $timertwitter = 0;
		 }
	    }
	    $timertwitter++;
       }
       
       	if ($timersavemsg > 8) {

              main::save_messages();
			 $timersavemsg = 0;

	    }
	    $timersavemsg++;
	
        if ($buildRoutes eq "yeah") {
	    if ($timerRoutes > 0) {
 	          my $checklaststuff = main::get_recv_last();

              my $pass1 = main::announce_list();
              my $pass2;
              my $pass3;
              if ($checklaststuff) {
              $pass2 = main::receive_announce($checklaststuff);# if defined $pass1;
              $pass3 = main::build_list($checklaststuff) if defined $pass2;
		      }
              #
              if ($pass2  && length($pass2) > 6 && $pass1 && length($pass1) > 6 ) {
              my $postitall = $pass1 . "  " . $pass2;
              main::gogogodispatch($postitall) if defined $postitall;
		      }
			 $timerRoutes = 0;

	      }
	    $timerRoutes++;
	    }
	#####
	
	
	######
	
	
	
}

##############################################################################

 {
 package AirChatServer;
 
 #use HTTP::Server::Simple::CGI;  #in case you went mad installing Net::Server module, and you need just a single threaded session etc...
 use HTTP::Server::Simple::CGI::PreFork;
 use HTML::Entities;
 use base qw(HTTP::Server::Simple::CGI);
 use Time::HiRes qw ( setitimer ITIMER_VIRTUAL time );


    
 my $style2use = qq{<link rel="stylesheet" type="text/css" href='style.cssv1'>};

 my $style = qq{

  \@font-face \{
      font-family: 'droid_sansregular';
      src: url('droidsans-webfont.eot');
    \}

  \@font-face \{
      font-family: 'droid_sansregular';
      src: url(data:application/x-font-woff;charset=utf-8;base64,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) format('woff'),
      url('droidsans-webfont.ttf') format('truetype');
      font-weight: bolder;
      font-style: normal;
    \}
	
	body      \{
                font-family : 'droid_sansregular';
			    background-color:#ffffff;
			  \}
			
  	p .content  \{
                font-family : 'droid_sansregular';
                max-width : 100px;
			  \}
							
							
	#logo     \{
			    height: 150px;
                width: 800px;
			    background-repeat: no-repeat;
			    background-image: url(data:image/png;base64,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);
			  \}
							
	a:link \{color: blue; text-decoration: underline; \}
    a:active \{color: blue; text-decoration: underline; \}
    a:visited \{color: blue; text-decoration: underline; \}
    a:hover \{color: blue; text-decoration: none; \}
							
    button, input, select, textarea \{
                font-family : 'droid_sansregular';
                font-size   : 100%;
              \}
              
    code      \{
                font-family : 'droid_sansregular';
                font-size   : 14px;
              \}
              
    #smallf   \{
                font-family : 'droid_sansregular';
                font-size   : 85%;
              \}
              
    #xsmallf  \{
                font-family : 'droid_sansregular';
                font-size   : 75%;
              \}
							
	#localnow \{
				color : green;
				font-family : 'droid_sansregular';
				font-size : 16px;
			  \}
			
	#attention\{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 14px;
			  \}
			
	#logfrom  \{
				color : gray;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#restart  \{
				color : gray;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#wait     \{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#isReady  \{
				color : green;
				font-family : 'droid_sansregular';
				font-size : 16px;
			  \}
			
	#localmsg \{
				color : blue;
				font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#sent     \{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#received \{
                font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#transmitting \{
                color : blue;
                font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	.greentxt \{
				font-family : 'droid_sansregular';
                color : green;
			  \}
					
 };
 
 
 my $favicon = qq{<link href='data:image/x-icon;base64,AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAADmhxgAAAAAAOaGFgDxvoIA54sfAPro0gDqmjsA99i0AOePJgDmhxcA9MmXAO+0bgDrn0UAAAAAAAAAAAAAAAAAERERERERERERERERERERERERFVd1URERERFaO7OlERERFavGbLpRERFatoRIa6UREVPICZCMNRERe2SSKUa3ERF7ZJIpRrcREVPICZCMNRERWraESGulEREVq8ZsulERERFaO7OlERERERVXdVERERERERERERERERERERERERH//wAA//8AAPgfAADwDwAA4AcAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAOAHAADwDwAA+B8AAP//AAD//wAA' rel="icon" type="image/x-icon" />};
 my $headerz = qq{Content-type: text/html; charset=UTF-8

    <html><title>Free Communications Over The Air</title><head>$favicon $style2use</head><body>};

 my $headerzmsg = qq{Content-type: text/html; charset=UTF-8

           <html><title>Free Communications Over The Air</title><head><meta http-equiv="refresh" content="30" >$favicon $style2use</head><body>};

my $ergumlogos = qq{<div id='logo'></div>};
 my $footerz = '</br></br></br></br></br></br></br></br><code><p>2014. Anonymous. All Your Base Are Belong To Us. </p></code></body></html>';
 
 my %dispatch = (
     '/' => \&msg_basic,
   #  '/advanced' => \&msg_advanced,  # this wasn't revisited lately, enable it and check it if you want 
     '/xtras' => \&msg_xtras,
     '/reconn' => \&tryreconnectfldigi,
     '/log.txt' => \&gimmelog,
     '/settings' => \&airchat_settings,
     '/addKey'    => \&add_buddy_key,
      '/delKey'    => \&del_buddy_key,
      '/publicKey.pem' => \&get_my_publickey,
      '/About'     => \&about_and_shits,
      '/crypt'     => \&msg_crypt,
      '/style.cssv1' => \&load_css,
      '/tables' => \&show_tables,
     # ...
 );
 
 sub load_css {
	 
	print qq{$style};
 }
 

 
 sub handle_request {
     my $self = shift;
     my $cgi  = shift;
   
     my $path = $cgi->path_info();
     my $handler = $dispatch{$path};
 
     if (ref($handler) eq "CODE") {
         print "HTTP/1.0 200 OK\r\n";
         $handler->($cgi);
         
     } else {
         print "HTTP/1.0 404 Not found\r\n";
         print $cgi->header,
               $cgi->start_html('Not found'),
               $cgi->h1('Not found'),
               $cgi->end_html;
     }
 }



 
 my $penispenis = " ";
 
 
 sub tryreconnectfldigi {

	 main::build_cmds();
	 main::modem_setting($currentmodem, $frequencycarrier);

    print qq{$headerz};


	     my $txstatus;
	     eval{$txstatus = main::get_tx_status()};
		if (defined $txstatus) {
			
					  print qq{<p>current fldigi status:  $txstatus . Shit looks fine, you can go back to default interface.</p></br></br></br>}; 
					  print qq{<a href="/">Go Back to the Messages</a>};			
				}else {
                     print qq{<p>Didn't work baby, verify fldigi is up and running and retry later </p>};
					 }	   
	print qq{</br></br></br></br></br>};
	print qq{$footerz};
	 
 }
 

 
 sub msg_basic {
     my $cgi  = shift;  
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 

     my $penis;

     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;
     
		 $txstatus = main::get_tx_status();
		 if (!$txstatus || !%methods) {
			 $txwarning = "\n\n<div id='attention'>ATTENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='logfrom'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }elsif ($txstatus =~ m/rx/){
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 if ($penis =~ m/^:local/ ) {
			 
		     }else {
				 $penis = ":local" . $penis;
			 }
			 main::sendingshits('00',$penis) if defined $penis;
			 main::get_last_msgs();
			 
		 }
		 
         if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};
		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
          
		 $pack2send = main::sendingshits('00',$penis) if defined $penis;
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);

         $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
         
         main::get_last_msgs();
	      }
	      
	   }else{
		 
		 }
		 
     print qq{$headerzmsg};
     print qq {<p style="text-align:right;font-size:14px;"><a href="/About" >WTF?!</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/log.txt" >log.txt</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/publicKey.pem" >My Public Key</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/crypt" >Encrypt</a>};
     
     if ($usedIp eq "127.0.0.1") {
		 print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/settings" >Settings</a>};
	 };
	 print qq {</p></br>};
	 
	 print qq{$ergumlogos};
	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post A Message Here (280 characters max)" maxlength=280 ></textarea></br></tr>
    <tr><input type="submit" style="height: 45px; width: 170px" value="Send Your Message" >};
    
    
    
    #####################

    #######################
    
    
    print qq{</form></tr></table>};
    if ($mybord) {
    print qq{<code></br></br><div id='transmitting' >Transmitting...  $mybord seconds to transmit your last message</div></br></code>};
    }
    if ($txstatus && $penis) {
       print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
    }
    if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning </pre></br></code>};
	}else{

	}
        
    print qq{</br>------------------------ Last  Messages ------------------------ </br>};


	if ($currentmessages) {
	print qq{$currentmessages};
    }else{
	print qq{<p>No Messages Yet.</p>};	
	}
	
	print qq{$footerz};

}
	 
	
sub msg_crypt {
     my $cgi  = shift;   
     return if !ref $cgi;
       
     my $usedIp = $cgi->remote_host(); 

     my $penis;
     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;

		 $txstatus = main::get_tx_status();
		 if (!$txstatus || !%methods) {
			 $txwarning = "\n\n<div id='attention'>ATTENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='logfrom'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }elsif ($txstatus =~ m/rx/){
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 if ($penis =~ m/^:local/ ) {
			 
		     }else {
				 $penis = ":local" . $penis;
			 }
			 main::sendingshits('00',$penis) if defined $penis;
			 main::get_last_msgs();
			 
		 }
		 
        if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};

		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
			 
			 
		################	 
		
		my $usekeyidx;
		
		if ($cgi->param('pubkeys') && length($cgi->param('pubkeys')) > 1 && $cgi->param('pubkeys') ne 'none' ) { 
			 	  
	     $usekeyidx = $cgi->param('pubkeys') ;
	      
        }
	 
	    #################### 
          
         if ( $usekeyidx ) {
   
		 $pack2send = main::sendingshits($usekeyidx,$penis) if defined $penis;
		 
	     }else{
			$pack2send = main::sendingshits('00',$penis) if defined $penis; 
		 }
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);


         $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
         
         main::get_last_msgs();
	 
	     }
	
	 }else{

		 }

     print qq{$headerzmsg};
     
     print qq {<p style="text-align:right;font-size:14px;"><a href="/About" >WTF?!</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/log.txt" >log.txt</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/publicKey.pem" >My Public Key</a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/" >Simple</a>};
     if ($usedIp eq "127.0.0.1") {
		 print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/settings" >Settings</a>};
	 };
	 print qq {</p></br>};
	 
	 print qq{$ergumlogos};
	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post A Message Here (280 characters max)" maxlength=280 ></textarea></br></tr>
    <tr><input type="submit" style="height: 45px; width: 170px" value="Send Your Message" >};
   
    #####################
    
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Encrypt Message to : <select name="pubkeys" >};
  
     print qq{<option size="15" value="none" >None (Do No Encrypt this time)</option>};
      foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( !$dahfuckingkeys{$publickey}{'Local'} ) {
		  
		  my $name = HTML::Entities::encode_entities_numeric($dahfuckingkeys{$publickey}{'name'}, '<>&"');
		  my $kcode = HTML::Entities::encode_entities_numeric($publickey, '<>&"');
	  
		  print qq{<option size="15" value="$kcode" >$name</option>};

	   }
		  
	  }
     print qq{</select>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/addKey" ><code>add a new key</code></a>};
    
    #######################
    
    
     print qq{</form></tr></table>};
      if ($mybord) {
        print qq{<code></br></br><div id='transmitting' >Transmitting...  $mybord seconds to transmit your last message</div></br></code>};
       }
      if ($txstatus && $penis) {
        print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
       }
      if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning </pre></br></code>};
	  }else{

	  }
     print qq{</br>------------------------ Last  Messages ------------------------ </br>};

                         

	
	if ($currentmessages) {
	print qq{$currentmessages};
    }else{
	print qq{<p>No Messages Yet.</p>};	
	}
	
	print qq{$footerz};
	

}
	
	
	
## this one wasn't re-visited lately. probably to be left out later	
sub msg_advanced {
     my $cgi  = shift;   
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {

     my $penis = " ";
     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;
     
     my $changemodemsettings;
     
     my $modifiedoptions;

		 $txstatus = main::get_tx_status();
		 if (!$txstatus) {
			 $txwarning = "\n\n<div id='attention'>ATENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='restart'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }else {
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 $penis = ":local" . $penis;
			 main::sendingshits('00',$penis) if defined $penis;
			 
		 }
		 
		 
     if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};

		 $txstatus = main::get_tx_status();

		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
			 
		 if ($cgi->param('encryption') && $cgi->param('encryption') eq "encrypt") {
			 if ($mustEncrypt eq "nones") {
			 $mustEncrypt = "yeahbabygetthisoneintoyourassFCCandNSA";
			 $modifiedoptions = "yeah";
		 }
			 if ($cgi->param('passphrase') ne $passphrase) {
				
			      $passphrase = $cgi->param('passphrase');
			      $modifiedoptions = "yeah";
			      
		      }
			 }else{
				 if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
				 $mustEncrypt = "nones";
				 $modifiedoptions = "yeah";
			 }
				 }
		 
		 if ($cgi->param('modes') ne $currentmodem) {
			 $currentmodem = $cgi->param('modes');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
		 
		 if ($cgi->param('freqcursor') ne $frequencycarrier) {
			 $frequencycarrier = $cgi->param('freqcursor');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
			 

		
		if ($cgi->param('answer2resend') && $cgi->param('answer2resend') eq "answresend" ) {
			
			if ($mustAnswerResendreq eq "nones" ) {
			$mustAnswerResendreq = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ($mustAnswerResendreq eq "yeahbaby" ) {
			$mustAnswerResendreq = "nones";
			$modifiedoptions = "yeah";
		   }

		}
		if ($cgi->param('askresend') && $cgi->param('askresend') eq "askresend" ) {
			if ( $mustAsk2resend eq "nones" ) {
			$mustAsk2resend = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ( $mustAsk2resend eq "yeahbaby" ) {
			$mustAsk2resend = "nones";
			$modifiedoptions = "yeah";
		   }
		}

        if ($changemodemsettings || $modifiedoptions )
        {
			main::save_settings();
			undef $modifiedoptions;
		}
        

		if ($changemodemsettings && $changemodemsettings eq "yeah") {
			main::modem_setting($currentmodem, $frequencycarrier);
			undef $changemodemsettings;
		}


		


		 $pack2send = main::sendingshits('00',$penis) if defined $penis;
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);

        $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

	      }

	 }else{


     my  $epassphrase = HTML::Entities::encode_entities_numeric($passphrase, '<>&"') if defined $passphrase; 
     my  $ecallsign = HTML::Entities::encode_entities($callsign) if defined $callsign;
    
     my  $efrequencycarrier = HTML::Entities::encode_entities($frequencycarrier);

     print qq{$headerzmsg};
	 print qq{$ergumlogos};

	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post A Message Here (280 characters max)" maxlength=280 ></textarea></br></tr>
    <tr><td><input type="submit" style="height: 45px; width: 170px" value="Send Your Message" >};
    if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" checked>};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" >};
			}
			print qq{ Encrypt Message with Passphrase: <input name="passphrase" maxlength=140 placeholder="Post A Message Here (140 characters max)" value="$epassphrase" size=36></td></tr>
   <tr><td><div id='smallf'> Data Transmission Mode: <select name="modes">
  <option value="$currentmodem" selected>$currentmodem</option>
  <option disabled>---</option>
  <option value="BPSK31">BPSK31</option>
  <option value="QPSK31">QPSK31</option>
  <option value="QPSK250">QPSK250</option>
  <option value="QPSK500">QPSK500</option>
  <option value="PSK500R">PSK500R</option>  
  <option value="PSK1000R">PSK1000R</option>

 <option value="PSK63RC5">PSK63RC5</option>
<option value="PSK63RC10">PSK63RC10</option>
<option value="PSK63RC20">PSK63RC20</option>
<option value="PSK63RC32">PSK63RC32</option>
<option value="PSK125RC12">PSK125RC12</option>
<option value="PSK125RC16">PSK125RC16</option>
</select> &nbsp;&nbsp;&nbsp;&nbsp;Carrier Frequency center:<input name="freqcursor" maxlength=4 value="$efrequencycarrier" size="4"></div></td></tr><tr><td><div id='smallf'>Automatically:&nbsp;&nbsp;};

      if ( $mustAsk2resend eq "yeahbaby") {
	    print qq{<input type="checkbox" name="askresend" value="askresend" checked>};
	  }else{
		print qq{<input type="checkbox" name="askresend" value="askresend" >};
		}
	 print qq{Ask others to resend messages when I received them corrupted&nbsp;&nbsp;&nbsp;&nbsp;  };
	
      if ( $mustAnswerResendreq eq "yeahbaby" ) {
	    print qq{<input type="checkbox" name="answer2resend" value="answresend" checked>};
	  }else {
		print qq{<input type="checkbox" name="answer2resend" value="answresend" >};
		}
		
	 print qq{Answer requests from others to resend messages</div></td></tr><tr><td><div id='xsmallf'>(resending back and forth can be annoying, use it only when needed)</div></td> </form></tr></table>};
      if ($mybord) {
        print qq{<code></br></br>Transmitting...  $mybord seconds to transmit your last message</br></code>};
       }
      if ($txstatus && $penis) {
        print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
      }
      if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning</pre></br></code>};
	  }else{
	  }
     print qq{</br>------------------------ Last  Messages ------------------------ </br>};

     if ($currentmessages) {
	    print qq{$currentmessages};
      }else{
	    print qq{<p>No Messages Yet.</p>};	
	  }
	
	 print qq{$footerz};
       }
   }
}
	 
	 
sub msg_xtras {
	
     my $cgi  = shift;  
     return if !ref $cgi;
       
     print qq{$headerz};
	 print qq{$ergumlogos};
   
    	 my $sentmsgs;
		 
		 
     print qq{<p>--- Recently Transmitted Packets ---</p></br></br>};		 
     print qq{<code><pre>};		 
     
		    foreach my $message (sort { $awesomessages{$b}{'timestamp'} <=> $awesomessages{$a}{'timestamp'} } keys %awesomessages) {
             if ( $awesomessages{$message}{'pack'} && length($awesomessages{$message}{'pack'}) > 10 )
                   {
					  $sentmsgs = $awesomessages{$message}{'pack'} ;
					  $sentmsgs = HTML::Entities::encode_entities($sentmsgs);
					  
					  print qq{</br></br>---------------------------------------------------</br></br>};
                   }
              }
    
     print qq{</pre></code>};
     print qq{</br></br></br></br></br></br>$footerz};
     
     
 }
 
sub gimmelog {
	 
	 if ($currentlogtxt) {
		print $currentlogtxt;
		 }
		 
 }
 
sub airchat_settings {
	
     my $cgi  = shift;  
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {

     my $reload;
     my $changemodemsettings;
     my $modifiedoptions;
    
     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Save Preferences" ) {

	 	if ($cgi->param('mustListenAll') && $cgi->param('mustListenAll') eq "yeahyeah" && $mustListenAllInterfaces eq "nones") {
		 $mustListenAllInterfaces = "yeah";
		 $pid->host('0.0.0.0');
		 #$pid->run();
		 $pid->run(prefork => 1);
		 # more elegant solution?
         
          }
         if ($cgi->param('mustListenAll') && $cgi->param('mustListenAll') ne "yeahyeah" && $mustListenAllInterfaces eq "yeah") {
		 $mustListenAllInterfaces = "nones";
		 $pid->host('127.0.0.1');
		 #$pid->run();
		 $pid->run(prefork => 1);
		
          }
	 
	 	    if ($cgi->param('mustUseProxy') eq "direct") {
		 $mustUseProxy = "nones";
	     }
	 	 if ($cgi->param('mustUseProxy') eq "useTor") {
		 $mustUseProxy = "useTor";
		    if ($cgi->param('torproxyhost') && $cgi->param('torproxyhost') =~ /(^\d+\.\d+\.\d+\.\d+$)/ ) {
	
				$torproxyhost = $cgi->param('torproxyhost');
			}	 
		 	if ($cgi->param('torproxyport') && $cgi->param('torproxyport') =~ /(^\d+$)/ ) {
	
				$torproxyport = $cgi->param('torproxyport');
			}	
	     }
	     if ($cgi->param('mustUseProxy') eq "useProxy") {
		 $mustUseProxy = "useProxy";
		 	if ($cgi->param('proxyhost') && $cgi->param('proxyhost') =~ /(^\d+\.\d+\.\d+\.\d+$)/ ) {
	
				$proxyhost = $cgi->param('proxyhost');
			}	 
		 	if ($cgi->param('proxyport') && $cgi->param('proxyport') =~ /(^\d+$)/ ) {
	
				$proxyport = $cgi->param('proxyport');
			}	
		 	if ($cgi->param('proxyuser') && length($cgi->param('proxyuser')) > 2 ) {
	
				$proxyuser = $cgi->param('proxyuser');
			}else{
				undef $proxyuser;
			}	
			if ($cgi->param('proxypass') && length($cgi->param('proxypass')) > 2 ) {
	
				$proxypass = $cgi->param('proxypass');
			}else{
				undef $proxypass;
			}		

	     }
	 
	    if ($cgi->param('mustNewsBroad') && $cgi->param('mustNewsBroad') eq "gimmeNews") {
		 $mustNewsBroadcast = "yeahcool";

	 }else{
		 $mustNewsBroadcast = "nones";

	 }
	 
   ########## twitter ##############
	 
	 	if ($cgi->param('mustTweet') && $cgi->param('mustTweet') eq "beCoolAndTweet" ) {
		 $mustTweetOthers = "yeahcool";
	 }else{
		 $mustTweetOthers = "nones";
	 }
	 if ($cgi->param('mustTweetBroad') && $cgi->param('mustTweetBroad') eq "TweetEmAll") {
		 $mustTweetBroadcast ="yeahcool";
	 }else{
		 $mustTweetBroadcast ="nones";
	 }
	 
	 if ($cgi->param('consumerKey') && length($cgi->param('consumerKey')) > 10 ) {
		 $consumer_key = $cgi->param('consumerKey');
	 }else{
		 $consumer_key = $consumer_key_default;
	 }
	 if ($cgi->param('consumerSecret') && length($cgi->param('consumerSecret')) > 10 ) {
		 $consumer_secret = $cgi->param('consumerSecret');
	 }else{
		 $consumer_secret = $consumer_secret_default;
	 }
	 if ($cgi->param('axxToken') && length($cgi->param('axxToken')) > 10 ) {
		 $access_token = $cgi->param('axxToken');
	 }else{
		 $access_token = $access_token_default ;
	 }
	 if ($cgi->param('axxTokenSecret') && length($cgi->param('axxTokenSecret')) > 10 ) {
		 $access_token_secret = $cgi->param('axxTokenSecret');
	 }else{
		 $access_token_secret = $access_token_secret_default ;
	 }
	 
	 #################################
	 #penis 
	 
	 ########## custom rss feeds ################
	 
	 	if ($cgi->param('mustCommunityBroad') && $cgi->param('mustCommunityBroad') eq "gimmeUpdates") {
		 $mustCommunityBroadcast = "yeahcool";
		 
		 
		 if ($cgi->param('feedlist') && length($cgi->param('feedlist')) > 20) {
			 @communityfeeds = split("\n",$cgi->param('feedlist'));
			 
		 }else{
			 undef @communityfeeds;
		 }
		 
	 }else{
		 $mustCommunityBroadcast = "nones";
	 }
	 
	 ##########################################
	 
	 ############ transmission options #############
	 
	 		 if ($cgi->param('encryption') && $cgi->param('encryption') eq "encrypt") {
			 if ($mustEncrypt eq "nones") {
			 $mustEncrypt = "yeahbabygetthisoneintoyourassFCCandNSA";
			 $modifiedoptions = "yeah";
		 }
			 if ($cgi->param('passphrase') ne $passphrase) {
				
			      $passphrase = $cgi->param('passphrase');
			      $modifiedoptions = "yeah";
			      
		      }
			 }else{
				 if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
				 $mustEncrypt = "nones";
				 $modifiedoptions = "yeah";
			 }
				 }
		 
		 if ($cgi->param('modes') ne $currentmodem) {
			 $currentmodem = $cgi->param('modes');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
		 
		 if ($cgi->param('freqcursor') ne $frequencycarrier) {
			 $frequencycarrier = $cgi->param('freqcursor');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
			 
		if ($cgi->param('answer2resend') && $cgi->param('answer2resend') eq "answresend" ) {
			
			if ($mustAnswerResendreq eq "nones" ) {
			$mustAnswerResendreq = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ($mustAnswerResendreq eq "yeahbaby" ) {
			$mustAnswerResendreq = "nones";
			$modifiedoptions = "yeah";
		   }

		}
		if ($cgi->param('askresend') && $cgi->param('askresend') eq "askresend" ) {
			if ( $mustAsk2resend eq "nones" ) {
			$mustAsk2resend = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ( $mustAsk2resend eq "yeahbaby" ) {
			$mustAsk2resend = "nones";
			$modifiedoptions = "yeah";
		   }
		}

        
        #### callsign ########
        
        	 if ($cgi->param('useCallsign') && $cgi->param('useCallsign') eq "usethisCallsign") {
			    if ($mustUseCallSign eq "nones") {
			       $mustUseCallSign = "yeah";
			       $modifiedoptions = "yeah";
		         }
			    if ($cgi->param('callsign') && length($cgi->param('callsign')) >= 2 ) {
				
			        $callsign = $cgi->param('callsign');
			        $modifiedoptions = "yeah";
			      
		          }else{
					 undef $callsign;
					 $mustUseCallSign = "nones";
				 } 
			 }else{
				 if ($mustUseCallSign eq "yeah") {
				   $mustUseCallSign = "nones";
				   $modifiedoptions = "yeah";
				   #undef $callsign;
			     }
			}
        
        
        ################
        

		if ($changemodemsettings && $changemodemsettings eq "yeah") {
			main::modem_setting($currentmodem, $frequencycarrier);
			undef $changemodemsettings;
		}
	 
	 #######################################################
	 
	 
	 main::save_settings();
 }
    my  $etorproxyhost = HTML::Entities::encode_entities($torproxyhost); 
    my  $etorproxyport = HTML::Entities::encode_entities($torproxyport);
    my  $eproxyhost = HTML::Entities::encode_entities($proxyhost);
    my  $eproxyport = HTML::Entities::encode_entities($proxyport);
    my  $eproxyuser = HTML::Entities::encode_entities($proxyuser) if defined $proxyuser;
    my  $eproxypass = HTML::Entities::encode_entities($proxypass) if defined $proxypass;
    
    my  $epassphrase = HTML::Entities::encode_entities_numeric($passphrase, '<>&"') if defined $passphrase; 
    my  $ecallsign = HTML::Entities::encode_entities($callsign) if defined $callsign;
    
    my  $efrequencycarrier = HTML::Entities::encode_entities($frequencycarrier);
    
    my  $econsumer_key = HTML::Entities::encode_entities($consumer_key);
    my  $econsumer_secret = HTML::Entities::encode_entities($consumer_secret);
    my  $eaccess_token = HTML::Entities::encode_entities($access_token);
    my  $eaccess_token_secret = HTML::Entities::encode_entities($access_token_secret);
     
     print qq{$headerz};
     print qq {<p style="text-align:right;font-size:18px;"><a href="/" >Back To Messages</a></p></br>};
	
	 print qq{$ergumlogos};
    
     print qq{<h2> Internet Gateway Services</h2><form name="formGateway" method="POST" >};
    
     print qq{<input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Preferences" ></br></br>};

     print qq{<h3> AirChat Server Access </h3></br>};
   
    if ($mustListenAllInterfaces eq "yeah") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustListenAll" value="yeahyeah" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustListenAll" value="yeahyeah" />};
			}	
			print qq{Do You Want to make AirChat available for all users on your network? </br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;By default AirChat listens for all incoming connections , 
			</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if you want to make it available only for localhost uncheck this,</br>
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;advanced settings like these ones are available only from localhost.};
	  print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Refresh This Page after Changing This Setting.)</code></br></br>};
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>Contacts:</b>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/addKey" ><code>add a new key</code></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/delKey" ><code>delete an existent key</code></a>};

    #no, we didnt forget weev.. <3
    print qq{<h3> News </h3></br>};
    
    if ($mustNewsBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustNewsBroad" value="gimmeNews" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustNewsBroad" value="gimmeNews" />};
			}	
			print qq{Do You Want to broadcast News to other users, over the air, from your internet access? </br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Really simple. Keep other people, without access to internet, informed about what is going on.</br></br>};

   print qq{<h3> Community News and Personalized Feeds </h3></br>};
    
    if ($mustCommunityBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustCommunityBroad" value="gimmeUpdates" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustCommunityBroad" value="gimmeUpdates" />};
			}	
			print qq{Do You Want to broadcast updates related to your Community to other users, over the air, from your internet access? </br>
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Keep other people, without access to internet, updated about your community.</br></br>};
       
       
       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Paste here URLs of those RSS you want to broadcast (one address per line):</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};

	   if (@communityfeeds) {
		   my $listfeeds = join("\n",@communityfeeds);
		   $listfeeds = HTML::Entities::encode_entities($listfeeds);
       		   print qq{<textarea name="feedlist" rows="6" cols="100"  placeholder="http://megacool.org/lastnyancatfeed.xml" maxlength=500 >$listfeeds</textarea>};

       }else{
		       print qq{<textarea name="feedlist" rows="6" cols="100" placeholder="http://megacool.org/lastnyancatfeed.xml" maxlength=500 ></textarea>};
   
	   }
	  print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Verify your links are correct and available or they will be ignored otherwise.)</code>};


     print qq{</br></br><h3> Twitter </h3></br>};
     
      if ($mustTweetOthers eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweet" value="beCoolAndTweet" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweet" value="beCoolAndTweet" />};
			}
			print qq{Do You Want to offer other users to send tweets via your internet access?</br></br>};
			
		      if ($mustTweetBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweetBroad" value="TweetEmAll" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweetBroad" value="TweetEmAll" />};
			}	
			print qq{Do You Want to broadcast twitter streams, over the air, from your internet access? </br></br>};
			
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Look below for instructions how to setup and general help about this.)</code>};

     print qq{</br></br></br><p>Twitter OAuth required credentials:</p>};

     print qq{<table>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Consumer Key:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input name="consumerKey" maxlength=90 placeholder="$econsumer_key" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Consumer Secret:&nbsp;&nbsp;&nbsp;&nbsp;<input name="consumerSecret" maxlength=90 placeholder="$econsumer_secret" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Access Token:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input name="axxToken" maxlength=90 placeholder="$eaccess_token" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Access Token Secret:&nbsp;&nbsp;&nbsp;&nbsp;<input name="axxTokenSecret" maxlength=90 placeholder="$eaccess_token_secret" value="" size="90"></div></td></tr>};




     print qq{</table></br></br><p>WTF?!?! how the fuck do I get this done?</p>};

     print qq{<p>OK listen...first go to Twitter and sign in for the new account you want to dedicate to this stuff.</br> Once you get all done, go to the Twitter Developer page and login using this new account credentials.</br> then create a New Application, get the consumer key and consumer secret values and put them here,</br> then request new tokens with writting rights and fill token access key and token access secret fields here.</br>then save and enjoy your mojito</p>};

     print qq{<p>hmmm...well..if you are still feeling lost then check the following tutos about how to do it:</br>

<a href="http://www.themepacific.com/how-to-generate-api-key-consumer-token-access-key-for-twitter-oauth/994/">How to Generate API Key, Consumer Token, Access Key for Twitter OAuth</a></br>
<a href="http://www.themebeans.com/how-to-create-access-tokens-for-twitter-api-1-1/">How to Create your Access Tokens for Twitter</a></br>
</br></br></br>
};

       print qq{<h3> Tor and Proxy </h3></br>};
       
          if ($mustUseProxy eq "nones") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="direct" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="direct" />};
			}	
			print qq{Direct Access to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</br></br></br></br></br>};

    
    if ($mustUseProxy eq "useTor") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useTor" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useTor" />};
			}	
			print qq{Use Tor to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
     print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Tor Service Listening at : &nbsp;&nbsp;<input name="torproxyhost" maxlength=24 value="$etorproxyhost" placeholder="Tor Service IP Address" size="12">&nbsp;&nbsp;&nbsp;&nbsp;Port:&nbsp;&nbsp;<input name="torproxyport" maxlength=5 value="$etorproxyport" placeholder="Port" size="5"></br></br></br></br>};
    
      if ($mustUseProxy eq "useProxy") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useProxy" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useProxy" />};
			}	
			print qq{Use a Proxy to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
		
     print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Proxy IPv4 Address: &nbsp;&nbsp;http://<input name="proxyhost" maxlength=24 value="$eproxyhost" placeholder="Proxy address" size="12">&nbsp;&nbsp;&nbsp;&nbsp;Port:&nbsp;&nbsp;<input name="proxyport" maxlength=5 value="$eproxyport" placeholder="Port" size="5">};

     if ($eproxyuser && length($eproxyuser) > 2) {
      print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User: <input name="proxyuser" maxlength=24 value="$eproxyuser" placeholder="User" size="10">};
       }else{
	   print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User: <input name="proxyuser" maxlength=24 value="" placeholder="User" size="10">};
      }

     if ($eproxypass && length($eproxypass) > 2) {
       print qq{&nbsp;&nbsp;&nbsp;&nbsp; Password: <input name="proxypass" maxlength=64 value="$eproxypass" placeholder="Password" size="10">};
     }else{
	   print qq{&nbsp;&nbsp;&nbsp;&nbsp; Password: <input name="proxypass" maxlength=64 value="" placeholder="Password" size="10">};
      }

     print qq{</br></br></br></br></br><table>};

     print qq{<h3> Data Transmission Options</h3></br> <tr><td>};

   if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" >};
			}
			print qq{ Encrypt/Decrypt Messages with Passphrase: <input name="passphrase" maxlength=140 placeholder="Passphrase" value="$epassphrase" size=36>&nbsp;&nbsp;&nbsp; (AES-256)</td></tr>
   </tr></td><tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Data Transmission Mode: <select name="modes">
  <option value="$currentmodem" selected>$currentmodem</option>
  <option disabled>---</option>
  <option value="BPSK31">BPSK31</option>
  <option value="QPSK31">QPSK31</option>
  <option value="QPSK250">QPSK250</option>
  <option value="QPSK500">QPSK500</option>
  <option value="PSK500R">PSK500R</option>  
  <option value="PSK1000R">PSK1000R</option>

  <option value="PSK63RC5">PSK63RC5</option>
<option value="PSK63RC10">PSK63RC10</option>
<option value="PSK63RC20">PSK63RC20</option>
<option value="PSK63RC32">PSK63RC32</option>
<option value="PSK125RC12">PSK125RC12</option>
<option value="PSK125RC16">PSK125RC16</option>
</select> &nbsp;&nbsp;&nbsp;&nbsp;Carrier Frequency center:<input name="freqcursor" maxlength=4 value="$efrequencycarrier" size="4"></div></td></tr>
<tr><td><div id='xsmallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(Do Not Change This, if you are not sure about what are you doing.)</div></td>
<tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Automatically: &nbsp;&nbsp;};

    if ( $mustAsk2resend eq "yeahbaby") {
	 print qq{<input type="checkbox" name="askresend" value="askresend" checked>};
	  }else{
		 print qq{<input type="checkbox" name="askresend" value="askresend" >};
		}
	print qq{Ask others to resend messages when I received them corrupted&nbsp;&nbsp;&nbsp;&nbsp;  };
	
    if ( $mustAnswerResendreq eq "yeahbaby" ) {
	 print qq{<input type="checkbox" name="answer2resend" value="answresend" checked>};
	   }else {
		print qq{<input type="checkbox" name="answer2resend" value="answresend" >};
		 }
		
	 print qq{Answer requests from others to resend messages</div></td></tr>
	<tr><td><div id='xsmallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(resending back and forth can be annoying, use it only when needed)</div></td></tr>};


     print qq{<tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
      if ($mustUseCallSign eq "yeah") {
		print qq{<input type="checkbox" name="useCallsign" value="usethisCallsign" checked>};
		}else{
			print qq{<input type="checkbox" name="useCallsign" value="usethisCallsign" >};
			}
			
			 if ($ecallsign) {
			print qq{ Include this Call Sign in your messages: <input name="callsign" maxlength=36 placeholder="Call Sign" value="$ecallsign" size=36>};
		 }else{
			 			print qq{ Include this Call Sign in your messages: <input name="callsign" maxlength=36 placeholder="Call Sign" value="" size=36>};
			 			

		 }
     print qq{&nbsp;&nbsp;(Optional)&nbsp;&nbsp;&nbsp;</div></td></tr>};

     print qq{</table></br></br></br></br></br>};

     print qq{<input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Preferences" ></form></br></br></br></br>};

     print qq{$footerz};
     
	}
 }  
 
sub show_tables {
	
	
	 print qq {Content-type: text/plain\n\n};
     print qq{######################################################\n};
     print qq{###                   TABLES                       ###\n};
     print qq{######################################################};
     print qq{\n\n================================================================\n\n};
	
	
	print qq{CAN LISTEN TO: \n};
	
	foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canListen'} ) {
		  
		    print qq{$contacted \n};
            
	   }
		  
	  }
	print qq{---------------------------------------\n\n};
	
	print qq{CAN TALK TO: \n};
	
		foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalk'} ) {
		  
		    print qq{$contacted \n};
            
	   }
		  
	  }
	
	print qq{---------------------------------------\n\n};
	
	print qq{CAN EXTENSIVELY TALK TO: \n};
	
		foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalkExtended'} ) {
		  
		    print qq{$contacted via $rtable{$contacted}{'via'}\n};
            
	   }
		  
	  }
	
} 
 
 
sub add_buddy_key {

	 my $cgi  = shift;   
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     my $addedkey;
     
     
     my $keyexample = qq{<code><pre>
How the fuck do this? 

Get the RSA public key from the radio node or the contact you want to
send encrypted messages to. 
Valid public keys are automatically generated for each Airchat node,
and that public key should be available at :

'http://someuser.Airchat.ip.address:port/publicKey.pem'

*Airchat automatically produces RSA keys of 2048 bits for its users
The RSA public key should look like this (well..something similar):

-----BEGIN RSA PUBLIC KEY-----
xxxxblah..blah..xxxxxx.blah..err...etc...random.characters...xxx
jKBf71aWKmUtkU96S4Gvi7M/oGX5dp5GCpY77eAWVxFB1OXvyVN40EhAowrDNtnL
.....xxxxxxxxxxx....blah..blah....................more.random..X
J5iKpZWksyP0W7V/KyPOuyINUO+9gKcMZ1DYCBdmuXT7oAEnobUH5Z3TweyWoygw
xxxxblah..Keith Alexander loves cocksxx..his hair is weird...xxx
xxxxblah..err...etc..also..c0cks...xxx
-----END RSA PUBLIC KEY-----


then write the name or something that can help you identify
the recipient whom public key belongs to,
then copy/paste the key on that box above and click on 'Save Public Key'
then enjoy.\n</pre></code>};
    
     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Save Public Key" ) {
	
	  
	  if ($cgi->param('contact') && length($cgi->param('contact')) >=1 && $cgi->param('publicKey') && length($cgi->param('publicKey')) >=100) {
	  
	     my $keytowrite = $cgi->param('publicKey') ;
	      
	      if ( ($keytowrite =~ m/-----BEGIN RSA PUBLIC KEY-----/) && ($keytowrite =~ m/-----END RSA PUBLIC KEY-----/) ) {
	  
          my @cleaning = split("-----BEGIN RSA PUBLIC KEY-----",$keytowrite);
          my @cleaning2 = split("-----END RSA PUBLIC KEY-----",$cleaning[1]);
          $keytowrite = $cleaning2[0];
          $keytowrite = "-----BEGIN RSA PUBLIC KEY-----" . $keytowrite . "-----END RSA PUBLIC KEY-----\n";
          $keytowrite =~ s/\r//g;
          
	      
	      my $kcode = main::sha512_hex($keytowrite,"");
	       $kcode = substr($kcode,0,6);	
	      
	      if ( $dahfuckingkeys{$kcode} && $dahfuckingkeys{$kcode}{'Local'} ) {
			  
		  }else{
	      
	      $dahfuckingkeys{$kcode}{'pubK'} = $keytowrite;
	      $dahfuckingkeys{$kcode}{'name'} = $cgi->param('contact');
	      
	      main::save_keys();
	      $addedkey = "<div class='greentxt'><h2> The new Public Key was Succesfully added  </h2></div></br>";
	       }
	       }
	  
 
	    }
   }

       print qq{$headerz};
       print qq {<p style="text-align:right;font-size:18px;"><a href="/crypt" >Back To Messages</a></p></br>};
	
	   print qq{$ergumlogos};
    
       print qq{<h2> Add a new RSA Public Key for your Contacts</h2></br><form name="formAddKey" method="POST" >};
     

       print qq{$addedkey} if $addedkey;
       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Name/Nick/Callsign/other : &nbsp;&nbsp;<input name="contact" maxlength=140 placeholder="something" value="" size=36>&nbsp;&nbsp;&nbsp; };
	   print qq{</br></br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <textarea name="publicKey" rows="15" cols="90"  placeholder="Paste the RSA Public Key here." maxlength=2000 ></textarea>};

       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Public Key" ></form></br></br></br>};
	    
	   print qq{$keyexample};
	    
	    
	   print qq{$footerz};
    
   
}

sub del_buddy_key {
     my $cgi  = shift;   
     return if !ref $cgi;
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {
		 
	 my $deletedkey;

     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Delete Public Key" ) {
		 
	  if ($cgi->param('pubkeys') && length($cgi->param('pubkeys')) >=1 ) {
	     my $keytodel = $cgi->param('pubkeys') ;
	      
          delete $dahfuckingkeys{$keytodel};
          main::save_keys();
         $deletedkey = "<div class='greentxt'><h2> The chosen Public Key was Succesfully deleted  </h2></div></br>";

	  
       }
	}


     print qq{$headerz};

     print qq {<p style="text-align:right;font-size:18px;"><a href="/settings" >Back To Settings</a></p></br>};
	
     print qq{$ergumlogos};
    
     print qq{<h2> Delete a Public Key </h2></br><form name="formDelKey" method="POST" >};
     
     print qq{$deletedkey} if $deletedkey;
     
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Choose a Public Key to delete by its linked Name/Nick/Callsign/other : <select name="pubkeys" placeholder="Choose...">};
      foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( !$dahfuckingkeys{$publickey}{'Local'} ) {
		  
		  my $name = HTML::Entities::encode_entities_numeric($dahfuckingkeys{$publickey}{'name'}, '<>&"');
		  my $kcode = HTML::Entities::encode_entities_numeric($publickey, '<>&"');
		  
		  print qq{<option size="15" value="$kcode" >$name</option>};
	   }
		  
	  }
     print qq{</select></br></br>};

     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Delete Public Key" ></form></br></br></br></br>};
	 print qq{$footerz};
	
   }
}


sub get_my_publickey {
	print "Content-type: text/plain\n\n";
	foreach my $publickey (sort { $dahfuckingkeys{$a} cmp $dahfuckingkeys{$b} } keys %dahfuckingkeys) {
	if ( $dahfuckingkeys{$publickey}{'Local'} ) {
	
	print $dahfuckingkeys{$publickey}{'pubK'};
    }
     }
}


sub about_and_shits {
	
	my $diagram1 = '<img width="900" src="data:image/png;base64,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" alt="diagram1" />';
	my $diagram2 = '<img width="900" src="data:image/png;base64,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" alt="diagram2" />';
	
	my $preintro = qq{
<b>Why Airchat?</b>
Because we strongly believe communications should be free,
Free as much as the air itself and all the waves should be.
Free for everyone everywhere, free for those oppressed, free for the poor,
free for the dissident, free for those living out of the boundaries
of the infrastructure created for those who were lucky enough to have more than others.
And free...well... because sometimes the non-free infrastructure itself fails.
 
 
Several thousands years ago, we started shouting into the air to
communicate, to build our first communities and to survive.
Since then the power of our voices has travelled through the air,
carrying poetry, intelligence, knowledge, art, emotions, science,
revolutions, philosophy, faith, evil, war,
Transmitting all those ideas, good or bad, which define us as human.
 
We freely shouted to the air our very own existence.
We shouted to the wind we were alive.
 
Several thousands of years after we started this adventure, we have built
amazing and technologically sophisticated networks to serve us
to communicate everywhere,
Now the fire of our freedom is burning away.
Our voices, once free,  are subject to uncountable controls, financial
fees, patents, rights, regulations, government censorship, etc.
 
 
Today, we have acknowledged that, even after all these years of technology advance, 
we still need to meet in common public places to continue expressing ourselves in a free way,
to build up our sense of community and stand up for our future and rights. 
Our so advanced communication infrastructure has failed to make us a better family, to make us better humans,
to bring us openness, democratic access and freedom to think nor to speak. 
Our pay-to-participate infrastructure identifies us, targets us, monitors us, controls us.
so then, we will try to go to the origin of all and try to scale up all these really very human voices 
to cover not only those tiny public spaces
but a whole community, a neighbourhood,
a big town, a huge city, a remote region... the world.
 
 
So...That's why Airchat,
because next time you want shout your freedom to the wind, perhaps someone will hear you.
 
};
	
	my $intro1 = qq{<p class="content" >	
Airchat is a free communication tool, free as in 'free beer' and free as in 'jeremy hammond must be freed'.
It doesn't need the internet infrastructure, nor does it need a cellphone network,
instead it relies on any available radio link (or any device capable of transmitting audio -
we even made a prototype working with light/laser based transmissions).

This project was conceived not only from our lessons learned in the Egyptian, Libyan and Syrian revolutions,
but also from the experience of OccupyWallStreet and Plaza del Sol.
We have considered the availability of extremely cheap modern radio devices (like those handhelds produced in China),
to start thinking about new ways in which people can free themselves from expensive, commercial, 
government controlled and highly surveilled infrastructure.

AirChat is not only our modest draft or proposal for such a dream, but it is a working PoC you can use today.
we hope you will enjoy it and we also hope that you too will be able to feel the beauty of free communications,
free communications as in 'free beer' and free communications as in 'free yourself and your people forever'.

</p>};
	
	my $usercases = qq{	
<h2>User cases</h2><p class="content" >
People who were protesting against their govt resulting in the their internet being cut off. 
Even worse govt decided to fuck with their cellphones networks too. 
They need basic communication tools to spread news and updates about their conditions, 
and with the aim to eventually relay that information to/from the internet 
when at least one of them is able to get a working internet connection.

NGOs and medical teams working in Africa under poor conditions who want to build some
basic communication's infrastructure to coordinate efforts like the delivery of 
medication and food or to update on local conditions 
without being intercepted by regional armed groups etc.

Dissident groups who mistrust the normal communication infrastructure and who want to coordinate
regional activity and share updates about oppressive actions carried out by the authorities.

Disaster response, rescue and medical teams who are working in devastated zones without the availability 
of standard telecommunication infrastructure. They want to keep updating their statuses, 
progress and resource availability between teams when there may be large overage zones between them.

Yacht owners who are sailing and who wish to obtain news updates from some approaching coastline
or another ship which has internet access. There may just be a simple exchange of information 
about news, weather conditions, provisions, gear etc.

Local populations who want to keep in touch with each other on a daily basis with the goal of developing 
a strong community capable of maximizing their resources, 
food or manpower to help improve sustainability and their quality of life.

Street protests or any other street event where people would like to share their thoughts, 
anonymously and locally without relying on the internet. They may also wish to share them 
with the world as a single voice using a simple gateway such as a unique Twitter account made for the occasion.

Expedition basecamps who need a simplistic solution to build a common gateway for establishing 
radio communication and messaging service links with camps, remotely located basecamps and/or 
rescue teams to coordinate tasks such as logistics, rescue efforts, routes and schedules.
</p>};

my $dilemmas = qq{
<h2>Background: Dilemmas and decisions</h2>
Every project is a fractalized representation of infinite dilemmas sparkling other new ones,
glued to the futile decisions we make, to try to address all of them.

Many ideas have crossed our minds when we tried to make this thingie.
We experimented broadcasting UDP packets inside mesh network solutions.
We experimented using patched wireless network card drivers to inject crafted wifi management frames.
We also considered crafting TDMA packets via cellphones RF hardware.
We thought about those many different possibilities. we saw there's so much potential on them. 
Sadly we found out how locked down and overregulated our communication devices are.

So, we thought: 'Well some solutions would require that we ask people to root their phones or routers, and 
to then install custom firmwares with patched drivers, with the risk of getting people mad cause they
were bricking them'

we also thought about a Wifi interconnected cellphone net approach, but the coverage range was frustrating.

We saw people working on different mesh related projects and we thought 
'One solution shouldn't discard another one but it should try to complement it, 
to add interoperability and to allow heterogeneous systems'. 
As different serious projects are looking for solutions based on 802.11 standards we said, 
'WTF lets try to reinvent the wheel for exploration and fun'.

But to reinventing the wheel you need freedom. a freedom which we don't have much of in on our world 
of telecommunications, which is over-regulated by evil organizations like the FCC and similars shits around the world. 
So we choose the good ol' trusted ancient technology to start free.

Radio transceivers.
yeah, these shits rock.
we chose to sacrifice bandwidth for freedom.
Tune the frequency.
Define a protocol.
Transmit.
Enjoy.

So yeah we connected our 897Ds to our computers, we shouted out to our bros to tune in and then we started playing around.

Initially AirChat used code from 'minimodem' and then from 'soundmodem' sources but after suggestions 
from the ham radio people involved in ARES, we decided to make it modular to use the Fldigi software, 
a broadly deployed solution for use with ham radios.
Fldigi is controlled by means of XML-RPC calls which can be made even between remote systems 
(example: One workstation, connected to radio equipments is dedicated to listening to the radio frequencies 
constantly while another system is running AirChat etc.)
We are open to feedback about this decision, and we will offer different implementations if they're needed.

We ended up with a simple protocol packet: the Lulzpacket. This simple packet
contains information to verify there was no corruption during the transmission
and a random code to pseudo-identify the packet. We define the addresses of
nodes in the net by their ability to decrypt a given packet. Addresses are
derived from the hashes of asymmetric encryption keys, Every radio node
defines its own address by the pair of keys it has generated for itself and
the addresses change if users choose to regenerate their keys. Each node only
cares for what is being received. No hardware identification, no transmitter
plain identification. only packets matter. transmissions are anonymous. whenever 
an address is needed to reply to a packet, it is encrypted inside the packet.
Packets targetting specific addresses are encrypted and they must be decrypted
by the private key only the target possesses. Anyone trying to spoof an
address will not be able to decrypt the packet. 
Symmetrical encrypted packets are available also and can be used as an extra
layer too. General non-encrypted packets also available by default for general 
broadcasting and community discussion. (also for those people on some countries
where laws forbid encryption on certain radio frequencies, etc).
Disclaimer: 
we dont give a fucking shit about prohibitions over the use of encryption. fuck you NSA.

So the choice is yours. You can use it with encryption or without.
Encryption is part of the routing solution approach, non encrypted packets are linked
to general broadcast.
(remember that when you are in the middle of a massive crisis you probably wouldn't care much about the stupid FCC)

Airchat is our first service which implements this protocol. The current release right now focuses on
messaging and it can be used as a simplistic message board inside a LAN and to rely communications
between radio nodes. It has built-in internet gateway capabilities to offer users access to some basics such as tweeting, 
retrieving twitter streams, downloading news, community related articles, etc.
This gateway can can be used whenever an Airchat running station gains a working internet connection and choose to share it.
(this internet access can be anonymized via Tor and the built in proxy support).

The first release will be a minimal set of useful functionality, so that we can see what people
can do with it and what they would like to be able to do. We will continue to add more features based on your feedback.

So far we have played interactive chess games with people at 180 miles away. we have shared pictures
and established encrypted low bandwidth digital voice chats. We have 3D printed over distances of 80 miles and
transmitted medical orders at distances of over 100 miles.
All without phones or internet access.

So how does it feel when you are communicating freely?
it feels great...fucking great.



};

my $quickstart = qq{

<h2>Quick Start</h2><h3>Software Setup</h3>
<b>FreeBSD 10</b>
from a fresh server install:
<code>
# pkg install make
# pkg install perl-5.16.xx
# perl install-modules-airchat-freebsd.pl
</code>
then...
<code>
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork
</code>
that will get you the airchat server running,
keep in mind installing fldigi requires a graphical environment aka X
so,
1: you setup airchat to connect with a remote station running fldigi
2: install X and then:
<code>
# pkg install fldigi-3.xx.xx
</code>


<b>Windows</b>
Install Strawberry Perl >= 5.18 (the portable zip version fits well for example)
from http://strawberryperl.com/

Direct link:
http://strawberryperl.com/download/

Once you get perl installed, run in your perl shell:
<code>
# perl install-modules-airchat-windows.pl
</code>
Then install these modules via the cpanplus terminal:
<code>
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork --skiptest
</code>
Then install fldigi from:
http://www.w1hkj.com/download.html


<b>Linux (Debian / tested also on Ubuntu Trusty)</b>
Install some needed stuff:
<code>
# apt-get install make libcpanplus-perl libhttp-server-simple-perl libcrypt-cbc-perl libcrypt-rijndael-perl librpc-xml-perl libxml-feedpp-perl liblwp-protocol-socks-perl libnet-twitter-lite-perl libnet-server-perl
</code>
(There's an optional and commented "use Net::SSLGlue::LWP" before "use LWP::UserAgent" on airchat.pl (# apt-get install libnet-sslglue-perl),
This magically fixes LWP for https requests issues, when for example you want to include feeds only available via proxy to a https address,
if you don't have the updated libwww-perl 6.05-2 and liblwp-protocol-https-perl 6.04-2 available from repositories 
(should be available from the jessie repos thou)) but...
We strongly recommend you look to update libwww-perl and liblwp-protocol-https-perl to their latest versions, 
cause using SSLGlue will eventually break https access to the twitter API.

Check if you have updated packages for 'libnet-twitter-lite-perl' because you will need the Twitter API v1.1 support.
run:
<code>
# perl install-airchat-modules-linux.pl
</code>
^ this will install 'HTTP::Server::Simple::CGI::PreFork' (needed) and 'Net::Twitter::Lite::WithAPIv1_1'

If you want to install Fldigi on the same machine than Airchat then:
<code>
# apt-get install fldigi
</code>
(running fldigi requires a graphical environment)


<b>MacOS X</b>
Get XCode.
Launch XCode and bring up the Preferences panel. Click on the Downloads tab. Click to install the Command Line Tools. Check you got 'make' installed.
run:
<code>
# perl install-airchat-modules-macosx.pl
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork --skiptest
</code>

<b>General Notes</b>
Airchat runs by default on port 8080, connect your browser to (for Example: http://localhost:8080). READ THE CODE.
If you find some problem running airchat, 
please try updating modules and linked libraries.
we've found some issues related to outdated implementations.
(like '500 Bad arg length for Socket6::unpack_sockaddr_in6, length is 16, should be 28'
happening in Ubuntu Precise when enabling the Twitter gateway)

<b>Fldigi Setup</b>
run fldigi.
skip everything if you want but
you must configure audio devices to make it work with your capture device
and your audio output device. test if it's working capturing audio signals and playing audio.
and that's all.

(Note: keep your fldigi updated always)
};

my $hardwaresetup = qq{
<h3>Hardware Setup</h3>
Radio transceivers usually come with many different interfaces,
Each brand deploys different connectors even within their own range of models and
sadly there's usually no standard which they follow.

We understand that some people have experience using more expensive
radio equipments and will know how to link those transceivers to their computers.
As such we will focus on supporting the cheapest and most accesible models which are able
to offer the democratization of this solution worldwide even in the poorest regions.

We have considered cheap chinese vhf/uhf fm handheld transceivers
available worldwide at as low as \$40 bucks each.

These devices come with a Kenwood 2-pin connector composed by a 2.5mm jack and a 3.5mm one.
The 2.5mm jack transports the speaker signal and the 3.5mm serves as the microphone input.

We will make a very simple setup using the VOX function on the transceiver to avoid more complex PTT setups.

First connect some 2.5mm male to 3.5mm male cable between the speaker output on the radio and the
microphone input on your computer. 

Then take a stereo 3.5mm male to 3.5mm male cable and cut all of the small
cables inside except the red one (It should be a red cable which is connected to the middle ring of the jack).
<u><b>Only the red cable with the signal coming from the ring of the 3.5mm jack should be connected and nothing else.
(neither the tip, nor the ground (ground will be provided by the 2.5mm jack cable)).</b></u>

Once you are done, connect this customised cable to the microphone input on the
radio transceiver and then to the speaker output of your computer.

Finally, set the frequency everyone will use on the transceiver,
Don't forget to enable the VOX function (adjust the sensitivity to medium).
Modify the transmission timer to more than 2 minutes, set the radio speaker volume to approx. 50%,
tune the microphone sensitivity on your computer to base levels with medium boost (if needed) and finaly
set the computer headphones volume to around 70% or so and then you are ready to go. keep testing till
getting the best audio quality for your transmission.

Be careful about the quality of cables and soldering used, test the audio quality until getting the 
most optimal conditions possible, that will directly improve your transmissions.


};

my $questions = qq{
<h3>Some Questions...</h3><b>Audio transmission?</b>
Almost every single home in this world has a common AM and/or FM radio.
In such cases when not everyone is able to get some cheap radio transceiver,
everyone at least will be able to decode packets being transmitted via a pirate FM stations (or AM)
AM doesn't suffer the capture effect of FM. so under certain circumstances people could accomodate
around 18 or 20 parallel different packet transmissions on the same bandwidth used for voice transmissions.
also it turned out to be cheap and simple to link laptops and radios via the soundcard.
simple enough to allow easy-to-make road warrior RF enabled mobile stations.

<b>Bandwidth?</b>
We traded bandwidth for freedom, or to be more exact we traded bandwidth for freedom, simplicity and low cost.
which indeed are the real conditions needed to democratize this solution. so yeah. sorry about the
bandwidth but we do not regret it. We will be looking for solutions to this in the future but keep in mind that
'freedom, simplicity and low cost' won't be given up.

<b>Is 4K video streaming coming soon?</b>
no, like...no.

<b>and pics?</b>
We love pix. pix support is coming ofc. We have tested image transfers using Google's WebP format 
to try conserve bandwidth as much as possible, but the lack of support in several browsers 
has given us second thoughts. We will looking for further feedback about it.

<b>I want to cyber my girlfriend (who lives 20 miles away) without having NSA agents fapping to it, can I use this for it?</b>
ofc, man. thou we require your girlfriend to deliver tits or gtfo. (sorry but it's needed to help us on the datamining of frequencies
usage and transmission mode performance raw data through our Hadoop cluster of ARM servers, all those pix will be used for the datalink test..
err...derp)

<b>What happened to Sabu?</b>
He ended up working as a male prostitute for FBI, he usually wears a pinkish silk kimono in the evenings and he resides in Chattanooga. 
He recently betrayed his male prostitute co-workers cause he was jelly they were getting more attention than him. 
His sentencing is still being delayed by FBI. 

<b>Should Molly get on Jabber?</b>
Yes.

};


    $preintro =~ s/\n/\<\/br\>/g;
    $intro1 =~ s/\n/\<\/br\>/g;
    $usercases =~ s/\n/\<\/br\>/g;
    $dilemmas =~ s/\n/\<\/br\>/g;
    $questions =~ s/\n/\<\/br\>/g;
    $quickstart =~ s/\n/\<\/br\>/g;
    $hardwaresetup =~ s/\n/\<\/br\>/g;
    
		
	print qq{$headerz};

    print qq {<p style="text-align:right;font-size:18px;"><a href="/" >Back To Messages</a></p></br>};
	
    print qq{$ergumlogos};
    
    print qq{</br></br>$preintro};
    
    print qq{</br><h2> WTF is AirChat then?!?! </h2>};
    
    ### intro ###
    print qq{$intro1};
    print qq{$usercases};
    
    ### dilemmas ###
    print qq{$dilemmas};
    
    ### diagrams ####
    print qq{<h2>Some Possible RF Network Configurations</h2></br>};
    print qq{</br></br>$diagram1 </br></br></br>$diagram2</br></br>};
    
    ### quick start ###
    
    print qq{$quickstart};
    
    print qq{$hardwaresetup};
    
    ### questions ###
    print qq{$questions};
  
    
    
    print qq{$footerz};
	
}



 } 
 
 $SIG{ALRM} = sub {
	&refresh_last_msgs(); 

	alarm 30;};
        alarm 30;
 

 modem_setting($currentmodem, $frequencycarrier);

 my $cock;
        $cock = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
        $cock = gmtime(Time::HiRes::gettimeofday());
        print "\nStarted at:  $cock \n";

 $pid = AirChatServer->new($AirchatPort);
if ($mustListenAllInterfaces eq "nones") {
 $pid->host('127.0.0.1');
}
# $pid->run();
 $pid->run(prefork => 1);

#
