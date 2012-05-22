set title "ROC curve for number of MX queries in BotFlex"
set xlabel "Miss (FP) rate"
set ylabel "Detection (TP) rate"
set yrange[0.0:10.0]
set xrange[0.0:14.0]
set grid
set terminal png font "/Library/Fonts/Times New Roman.ttf, 11"
set output "mx.png" 

plot "n_mx.txt" using 3:2 title "Threshold for number of MX queries (BotFlex)" with linespoints lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5,"n_stats_mx_bh.txt" using 3:2 title "MX query-based detections (BotHunter)" with linespoints lc rgb 'red' lt 1 lw 2 pt 7 ps 1.5  
 







# ------------------------------------------------------------------------------------------------------------------------------------
#"scan_addr_c_ob.txt" using 3:2 title "Outbound critical address scan threshold" with linespoints lc rgb 'green' lt 1 lw 2 pt 7 ps 1.5
# yoffset = 0.02
# plot "smtp.txt" using 2:3 with linespoints lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5, "smtp.txt" u 2:($3+yoffset):1 with labels 


