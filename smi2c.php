<?php

$fd = fopen("smi-numbers-5.csv","r");
$type = "static const char *const if_types[] = {\n";
$typed = "static const char *const if_typesd[] = {\n";

while (($line = fgetcsv($fd)) !== FALSE) {
  $type .= "\"$line[1]\",\n";
  $typed .= "\"$line[2]\",\n"; 
}

$type .= "};\n\n";
$typed .= "};\n\n";

$outfd = fopen("iftypes.h","w");
fputs($outfd, $type);
fputs($outfd, $typed);
fputs($outfd, "#define NIFTYPES ((sizeof if_types)/(sizeof if_types[0]))\n");
fputs($outfd, "#define NIFTYPESD ((sizeof if_typesd)/(sizeof if_typesd[0]))\n");

