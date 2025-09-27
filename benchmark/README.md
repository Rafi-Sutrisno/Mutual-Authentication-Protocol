1) Install semua di requirement.txt
2) Setup protocol.py, ubah USE_PUF = True jika akan menggunakan MAC (RSA+PUF), atau USE_PUF = False jika hanya menguji pure-RSA
3) Jalankan uvicorn app:main --reload
4) Jalankan "locust -f <nama file> --headless -u 50 -r 5 --run-time 1m --host http://127.0.0.1:8000 --csv=<csv>"
locust -f rsa_locust.py --headless -u 50 -r 5 --run-time 3m --host http://127.0.0.1:8000 --csv=output_rsa  
locust -f puf_locust.py --headless -u 50 -r 5 --run-time 3m --host http://127.0.0.1:8000 --csv=output_puf  
Note: -u = jumlah user  
      -r = user awal  
      --run-time = waktu jalan locust  
      --host = URL uvicorn  
      --csv = output
Variabel-variabel tersebut dapat diganti sesuai keinginan