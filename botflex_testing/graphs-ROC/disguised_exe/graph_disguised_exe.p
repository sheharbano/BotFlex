set title "ROC curve for number of exe files with misleading extension in BotFlex"
set xlabel "Number of misses (FP)"
set ylabel "Number of detections (TP)"
set yrange[0.0:10]
set xrange[0.0:17]
set grid
set terminal png font "/Library/Fonts/Times New Roman.ttf, 11"
set output "disguised_exe.png" 

plot "n_disguised_exe.txt" using 3:2 title "Threshold for number of disguised exes" with linespoints lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5  
 







# ------------------------------------------------------------------------------------------------------------------------------------
#"scan_addr_c_ob.txt" using 3:2 title "Outbound critical address scan threshold" with linespoints lc rgb 'green' lt 1 lw 2 pt 7 ps 1.5
# yoffset = 0.02
# plot "smtp.txt" using 2:3 with linespoints lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1.5, "smtp.txt" u 2:($3+yoffset):1 with labels 


