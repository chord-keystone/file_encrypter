from sounddevice import rec, wait
from secrets import token_bytes
from numpy.fft import fft
from numpy import abs, max

class paranoid_random:
    
    def __init__(self, seed_size:int = 512):
        '''Paranoid random class: uses your audio to generate random numbers. 
        
        :param int seed_size: how many bytes to record in each chunk
        '''       

        # init some variables
        self.record :bytes = b""
        self.sample_rate :int = 48000
        self.n_samples :int = seed_size

        # call the sampler
        self.sample_noise()

    def sample_noise(self):
        
        # gets a sample of audio using sounddevice
        # why is this random? well, it's completely disassociated with anything going on in the computer.
        # this may not be 'random' per se, but it is very difficult to predict

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
        '''Returns random byte string from the sample. Calls the record function if out of bytes.
        
        :param int n_bytes: Number of bytes to request
        '''
        
        while n_bytes > len(self.record):
            self.sample_noise()

        to_return = self.record[:n_bytes]
        self.record = self.record[n_bytes:]

        # xor with token_bytes for an additional layer of randomness
        return bytes(x[0] ^ x[1] for x in zip(to_return, token_bytes(n_bytes)))
    
if __name__ == "__main__":
    
    pr = paranoid_random(1024)
    randomkey = pr.random_bytes(128)