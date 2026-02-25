from sounddevice import rec, wait
from secrets import token_bytes
from numpy.fft import fft
from numpy import abs, max, frombuffer

class paranoid_random:

    def __init__(self, seed_size:int = 512, mode:str="None"):

        self.record :bytes = b""
        self.sample_rate :int = 48000
        self.n_samples :int = seed_size
        self.sample_noise()
        
        if mode == "stat":
            from numpy import histogram, sqrt
            import matplotlib.pyplot as plt

            byte_arr = frombuffer(self.record, dtype='uint8')
            this_var = byte_arr.std()
            known_var = sqrt((256**2)/12)
            print(f"std sampled data: {this_var}, uniform dist. std: {known_var}")
            print(f"n. unique bytes: {len(set(self.record))}")
            print(f"n. bytes: {len(self.record)}")

            hist, bin_edges = histogram(byte_arr, bins=256, range=(0, 256))
            plt.bar(bin_edges[:-1], hist, width=1)
            plt.title("Histogram of Sampled Bytes")
            plt.xlabel("Byte Value")
            plt.ylabel("Frequency")
            plt.show()

            plt.plot(byte_arr)
            plt.title("Sampled Byte Values")
            plt.xlabel("Index")
            plt.ylabel("Byte Value")
            plt.show()

            fft_vals = abs(fft(byte_arr))
            plt.plot(fft_vals[1:len(fft_vals)//2])
            plt.title("FFT of Sampled Bytes")
            plt.xlabel("Frequency Bin")
            plt.ylabel("Magnitude")
            plt.show()

    def sample_noise(self):

        this_record = rec(self.n_samples//2,
            samplerate=self.sample_rate,
            channels=1, 
            dtype='int16').flatten()
        wait()

        # project to random uniform distribution:
        this_record = abs(fft(this_record))
        this_record = this_record/max(this_record)*255
        this_record = this_record.view('uint32')%256
        self.record += this_record[:len(this_record)//2].astype('uint8').tobytes()
        
    def random_bytes(self, n_bytes:int) -> bytes:
        
        while n_bytes > len(self.record):
            self.sample_noise()

        to_return = self.record[:n_bytes]
        self.record = self.record[n_bytes:]

        # even if someone gets access to the record, it's useless without cracking token_bytes
        return bytes(x[0] ^ x[1] for x in zip(to_return, token_bytes(n_bytes)))
    
if __name__ == "__main__":
    
    pr = paranoid_random(1024, "stat")
    randomkey = pr.random_bytes(128)