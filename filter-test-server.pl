#!/usr/bin/perl

# This is basically a dumb server that will listen for control connections.
# After receiving it, the protocol is very simple. Each command is followed
# by a newline. 
#
#  LOGIN <password>
#  Authenticates the client. 
#  Response:
#   OK
#  or
#   ERROR [message]
#
#  START [filterstring]
#  Starts tcpdump, listening on the specified filterstring, if applicable
#  Response:
#   OK
#  or
#   ERROR [message]
#
#  STOP
#  Stops tcpdump
#  Response:
#   RESPONSE <first>
#   RESPONSE <second>
#   ...
#   RESPONSE <nth>
#   OK
#  or
#   ERROR [message]
#
# Notes:
#  The filtsrstring can contain some special constricts:
#   %ME% -- is replaced with the client's ip address

use strict;
use warnings;

use IO::Socket;
use Switch;
use File::Temp qw(tempfile tempdir);
use POSIX ":sys_wait_h";
use IPC::Open3;
use Time::HiRes qw( usleep );

use constant LOCAL_ADDR         => '0.0.0.0';
use constant DEFAULT_PORT       => 7071;
use constant PATH_TCPDUMP       => "/usr/sbin/tcpdump";
use constant INTERFACE          => "eth0";
use constant PASSWORD           => "nra4ever"; # TODO: change this!
use constant REQUIRE_PASSWORD   => 0;

use constant MS                 => 1000;
use constant TCPDUMP_STARTUP_MS => MS * 100;

# Little state machine for connections
use constant UNAUTHENTICATED => 1;
use constant STOPPED => 2;
use constant STARTED => 3;

# Grab interrupts so we can clean up
$SIG{'INT'} = 'CLEANUP';
sub CLEANUP { exit(1); }

my $socket = new IO::Socket::INET ( 
				LocalHost => LOCAL_ADDR,
				LocalPort => DEFAULT_PORT,
				Proto => 'tcp', 
				Listen => 1, 
				Reuse => 1,
			);

unless($socket)
{
	die "Could not create socket: $!\n";
}

print "Listening on " . LOCAL_ADDR . ":" . DEFAULT_PORT . "...\n";

my $connections = 0;
while(1)
{
	my $client_sock = $socket->accept();
	my $remote_addr = $client_sock->peerhost();
	my $remote_port = $client_sock->peerport();
	my $child = fork();

	$connections++;

	if($child)
	{
		print "[$connections] *** Connection from $remote_addr:$remote_port\n";
	}
	else
	{
		&handle_connection($connections, $client_sock, $remote_addr, $remote_port);
		exit(0);
	}
}



sub handle_connection
{
	my $num         = shift;
	my $socket      = shift;
	my $remote_addr = shift;
	my $remote_port = shift;

	my $state = REQUIRE_PASSWORD ? UNAUTHENTICATED : STOPPED;
	my $pid      = 0;
	my $input;
	my $error;

	while(my $line = <$socket>)
	{
		# Remove the trailing newline (why doesn't chomp work here?)
		$line =~ s/(\n|\r)//g;

		# Split the line at the space
		$line =~ m/^(.*?)( (.*)|)\s*$/;
		my $command = $1;
		my $params  = $2;

		if($command ne "LOGIN")
		{
			# Clean up the line
			$params =~ s/\%ME\%/$remote_addr/g;
			$params =~ s/[^a-zA-Z0-9= .]//g;
		}

		print "[$num] $command($params)\n";

		# Check which state we're in
		switch($state)
		{
			case UNAUTHENTICATED
			{
				if($command eq "LOGIN")
				{
					if($params eq PASSWORD)
					{
						print "[$num] connection authenticated\n";
						print $socket "OK\n";
						$state = STOPPED;
					}
					else
					{
						print "[$num] invalid password given\n";
						print $socket "ERROR invalid password\n";
					}
				}
				else
				{
					print "[$num] Attempted to use command without authenticating\n";
					print $socket "ERROR please authenticate with 'LOGIN' first\n";
				}
			}

			case STOPPED
			{
				if($command eq "START")
				{
					($pid, $input, $error) = &start($num, $params);

					if($pid)
					{
						$state = STARTED;
	
						print "[$num] starting to listen\n";
						print $socket "OK\n";
					}
					else
					{
						print "[$num] Error: $error\n";
						print $socket "ERROR $error\n";
					}
				}
				else
				{
					print "[$num] invalid command received: $command\n";
					print $socket "ERROR invalid command in STOPPED state\n";
				}
			}

			case STARTED
			{
				if($command eq "STOP")
				{
					print "[$num] starting the process\n";

					kill('INT', $pid);
					my $i = 0;
					while(my $line = <$input>)
					{
						$i++;
						chomp($line);
						if(length($line))
						{
							print "[$num] $line\n";
							print $socket "RESPONSE $line\n";
						}
					}

					$state = STOPPED;
					print $socket "OK\n";
				}
				else
				{
					print "[$num] invalid command received: $command\n";
					print $socket "ERROR invalid command in STARTED state\n";
				}
			}
		}
	}

	print "[$num] *** Connection closed\n";
	close($socket);
}

# Returns an array of results:
#  [0] = pid (0 indicates an error)
#  [1] = input stream (only if pid is set)
#  [2] = error message
sub start
{
	my $num    = shift;
	my $filter = shift;
	my $command = PATH_TCPDUMP . " -n -i " . INTERFACE . " " . $filter;
	my $pid;

	print "[$num] Starting tcpdump:\n";
	print "[$num]  $command\n";

    $pid = open3(0, \*READ, \*ERROR, $command);

	if(!$pid)
	{
		return (0, 0, "couldn't start tcpdump: $!");
	}

	# Give it a chance to fail
#	sleep(1);
	usleep(TCPDUMP_STARTUP_MS);

	if(waitpid($pid, WNOHANG))
	{
		my $error = <ERROR>;
		chomp($error);
		# The program has exited, there's a problem
		return (0, 0, "tcpdump exited with error: $error");
	}

	return ($pid, \*READ, '');
}







