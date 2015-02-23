#!/usr/bin/perl
 
################################################################################
#
# nexpose2csv.pl
#
# parse nexpose files and outputs a csv file to STDOUT
# with a summary of findings per machine
#
#
# v1.0 16/12/2013 - Josep Fontana - Initial version
#
# TODO: 
# 


################################################################################
# init and argument parsing
################################################################################

# if a CPAN module is not installed, run
# $ perl -MCPAN -e 'install MODULE'
use warnings;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;

my $green = "\e[32m"; # originally "\e[32;40m"
my $bold = "\e[1m";
my $normal = "\e[0m";

my %options;
getopts( 'o:', \%options ) or HELP_MESSAGE();
my @files = @ARGV;
print "No input files!!!\n" if ( @files ~~ () );


################################################################################
# parsing nexpose files to prepare variables
################################################################################

# global variables that are filled while parsing files
my @hosts; 			# list of hosts
my @hostnames;		# list of 'host (hostname)' for the title bar of the csv
my @plugins; 		# list of all plugin id present in nexpose files
my %plugin_desc; 	# the key is the plugin id, the value is a string with the description
my %plugin_score; 	# the key is the plugin id, the value is a string with the criticality
my %findings; 		# nested hash with the host and the plugin as 1st and 2nd keys
my $current_host;	# current host
my $host_has_name;	# flag to mark that the first hostname has been taken
my @tags;			# used to store tag hierarchy of the current element

use XML::Parser;
my $parser = XML::Parser->new( Handlers => {
	Init => \&handle_doc_start,
	Final => \&handle_doc_end,
	Start => \&handle_elem_start,
	End => \&handle_elem_end,
	Char => \&handle_char_data,
});

# release the parser!
foreach $file (@files) {
	$parser->parsefile( $file );
}


################################################################################
# Debug
################################################################################

 # use Data::Dumper;
 # print "\n *** %findings ***\n\n";
 # print Dumper %findings;
 # print "\n *** \@hosts ***\n\n";
 # print Dumper @hosts;
 # print "\n *** \@hostnames ***\n\n";
 # print Dumper @hostnames;
 # print "\n *** \@plugins ***\n\n";
 # print Dumper @plugins;
 # print "\n *** %plugin_desc ***\n\n";
 # print Dumper %plugin_desc;
 # print "\n *** %plugin_score ***\n\n";
 # print Dumper %plugin_score;
 # exit;
 
################################################################################
# write output based on:
#   @hosts: list of hosts
#   @plugins: list of all plugin id present in nexpose files
#	%plugin_desc: the key is the plugin id, the value is a string with the description
#	%plugin_score: the key is the plugin id, the value is a string with the criticality
#   %findings: nested hash with the host and the plugin as 1st and 2nd keys and  
################################################################################


{
	# print the CSV file headers
	$, = ',';
	print "Severity,Test ID,Description",@hostnames,"\n";
}


# print each plugin line, ordered by risk factor
foreach $risk ('Critical', 'Severe', 'Moderate'){
	foreach $plugin (@plugins) {
		if ($risk ~~ $plugin_score{$plugin}) {
			print "$plugin_score{$plugin},$plugin,$plugin_desc{$plugin}";
			foreach $host (@hosts) {
				if ( $findings{$host}{$plugin} ) {
					print ',X';
				} else {
					print ',';
				}
			}
			print "\n";
		}
	}
}

exit;


################################################################################
# HANDLERS for the XML parser
################################################################################


# foreach $file (@files)
#	if !($file is well formed)
#		print " *** $file is not well formed: $!\n";
#		next;
#
#	start parsing $file
#
#	foreach node
#		$hostname = NexposeReport/nodes/node/name;
#		add $hostname to @hosts;
#
#		foreach test
#			$plugin = NexposeReport/nodes/node/test(id);
#			%findings{$hostname}{$plugin} = 'X';
#			if !(@plugins contains $plugin)
#				add $plugin to @plugins;
#				$plugin_desc = NexposeReport/nodes/node/test(pluginName);
#				%plugin_desc{$plugin} = $plugin_desc;
#				$plugin_score = NexposeReport/VulnerabilityDefinitions/vulnerability(cvssScore);
#				%plugin_score{$plugin} = $plugin_score;


sub handle_doc_start {
#	print "Start to parse document\n";
}


sub handle_elem_start {
	my( $expat, $name, %atts ) = @_;
	push(@tags, $name);

	if ( $tags[-1] eq 'node' ) {
		push ( @hosts, $atts{address} );					#print "XXX host $current_host\n";
		$current_host = $atts{address};
		$host_has_name = 0;
	} elsif ( $tags[-1] eq 'test' ) {
													unless(defined $findings{$hosts[-1]}{lc $atts{id}}) {
													#print "XXX  finding $atts{id}\n" ;
													
		$findings{$hosts[-1]}{lc $atts{id}} = 'X';
		}
	} elsif ( $tags[-1] eq 'vulnerability' ) {
		if (!(lc $atts{id} ~~ @plugins)) {
			push ( @plugins, lc $atts{id} );
			# remove any comma
			$plugin_desc{lc $atts{id}} = $atts{title};
			$plugin_desc{lc $atts{id}} =~ s/,//g;		#print "XXX    plugin $plugin_desc{lc $atts{id}}\n";
		
			# 0-3.9  belongs to Moderate
			# 4.0-7.4 belongs to Severe
			# 7.5-10 belongs to Critical
			my $risk;
			if ( $atts{cvssScore} <= 3.9 ) {
				$risk = "Moderate";
			} elsif ( $atts{cvssScore} <= 7.4 ) {
				$risk = "Severe";
			} else {
				$risk = "Critical";
			}
			$plugin_score{lc $atts{id}} = $risk;		#print "XXX      risk $risk\n";
		}
	}
}


sub handle_elem_end {
	my( $expat, $name ) = @_;
	
	pop(@tags);
	
	if ( $name eq 'node' ) {
		push ( @hostnames, $current_host );

		$current_host = '';
		$host_has_name = 0;
	}
}


sub handle_char_data {
	my( $expat, $hostname ) = @_;

	# if we are in a name tag inside names and this is the first hostname, then push it into hosts array
	if ( ($tags[-1] eq 'name') && (!$host_has_name) && ($tags[-2] eq 'names') ) {
		$current_host = $current_host . ' (' . $hostname . ')';
		$host_has_name = 1;
	}
}


sub handle_doc_end {
	#print "Finished!\n";
}


################################################################################
# progress bar
# taken from http://oreilly.com/pub/h/943# HANDLERS
################################################################################

sub progress_bar {
    my ( $got, $total, $width, $char, $object ) = @_;
    $width ||= 25; $char ||= '=';
    my $num_width = length $total;
    sprintf "|%-${width}s| Done %${num_width}s $object of %s ($green%.2f%%$normal)\r", 
        $char x (($width-1)*$got/$total). '>', 
        $got, $total, 100*$got/+$total;
}


################################################################################
# Help & Version
################################################################################

sub VERSION_MESSAGE {
	print "\nnexpose2csv.pl v1.0\n";
	exit();
}

sub HELP_MESSAGE {
	print "
parse nexpose files and outputs a csv file to STDOUT with a summary of findings per machine

Usage: perl nexpose2csv.pl --help --version file1.nexpose file2.nexpose ...

	--help			this help message

	--version		show version\n";
	exit();
}
