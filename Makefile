
apager:
	g++ -fpermissive -o apager apager.cpp magic.S -static -T layout.ld

hpager:
	g++ -fpermissive -o hpager hpager.cpp magic.S -static -T layout.ld

hpager3:
	g++ -fpermissive -o hpager3 hpager3.cpp magic.S -static -T layout.ld

dpager:
	g++ -fpermissive -o dpager dpager.cpp magic.S -static -T layout.ld

dynamic:
	g++ -fpermissive -o dynamic dynamic_apager2.cpp magic.S -T layout.ld