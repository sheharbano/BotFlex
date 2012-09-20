##! A collection of botflex specific data-types and utility functions related to the representation
##! of one data type as another. 

## The string used to format time in the function strftime()
## (see bro.bif)
const str_time = "%d/%m/%y %H:%M:%S" &redef;

## The evaluation mode to use (AND, OR or MAJORITY)
type evaluation_mode: enum { AND, OR, MAJORITY }; 

## Converts a string value such as 5mins to an interval, such as 300.0 (5*60). 
## For the time being, it does not accept intervals of the form 5.5mins. It will
## cast it to become 5.0 mins.  
function string_to_interval(str_interval: string): interval
	{
	local arr = split_n(str_interval, /[[:alpha:]]/, T, 1 );

	local str_quantity = arr[1];
	local int_quantity = to_int(str_quantity);
	local db_quantity: double;
	db_quantity = int_quantity;
 

	local str_unit = arr[2] + arr[3];
	
	if ( str_unit=="usec" || str_unit=="usecs" )
		return double_to_interval(db_quantity / 1000000);
	if ( str_unit=="sec" || str_unit=="secs" )
		return double_to_interval(db_quantity * 1);
	if ( str_unit=="min" || str_unit=="mins" )
		return double_to_interval(db_quantity * 60);
	if ( str_unit=="hr" || str_unit=="hrs" )
		return double_to_interval(db_quantity * 60 * 60);
	if ( str_unit=="day" || str_unit=="days" )
		return double_to_interval(db_quantity * 60 * 60 * 24);		
	}


## Converts a set of addr to a string with sep separating successive strings
## e.g. The set {1.1.1.1,2.2.2.2} with sep # will be converted to 
## "1.1.1.1#2.2.2.2#". 
function setaddr_to_string(setaddr: set[addr], sep: string ): string
	{
	local str="";
	for ( rec in setaddr )
		{
		str = str + fmt("%s",rec) + sep;
		}
	return str;
	}


## Converts a set of strings to a single string with sep separating successive strings
## e.g. The set {"one","two"} with sep # will be converted to "one#two#". 
function setstr_to_string(setaddr: set[string], sep: string ): string
	{
	local str="";
	for ( rec in setaddr )
		{
		str = str + rec + sep;
		}
	return str;
	}

## Converts a string evaluation_mode to the proper enum representative
## as defined in the enum datatype evaluation_mode defined in /utils/types.bro
function string_to_evaluationmode( str_ev: string ): evaluation_mode
	{
	if ( str_ev == "OR" )
		return OR;
	else if ( str_ev == "AND" )
		return AND;
	else if ( str_ev == "MAJORITY" )
		return MAJORITY;
	}

