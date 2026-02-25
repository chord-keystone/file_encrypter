from tonellishanks import tonellishanks
from struct import pack, unpack
# very basic elliptic curve cryptography calculations

class ec_curve:
    a:int = 530438
    p:int = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45

    def __init__(self, a:int=None, p:int=None):
        if a is not None:
            self.a = a
        if p is not None:
            self.p = p

class ec_point(ec_curve):
    x:int
    y:int

    def __init__(self, x:int, y:int|None=None):
        
        super().__init__() # get the curve
        self.x = x # assign the x point
        self.y = None

        # recover the y-point if not provided:
        if y is None:

            yt = (x*x*x + self.a*(x*x) + x)%self.p
            self.y = tonellishanks(yt, self.p)

        else:
            self.y = y #bold assumption

    def __add__(self, Q):

        xslope = pow((Q.x - self.x)%self.p, self.p-2, self.p)
        xslope_squared = pow(((Q.x - self.x)*(Q.x - self.x))%self.p, self.p-2, self.p)
        xslope_cubed = pow(((Q.x - self.x)*(Q.x - self.x)*(Q.x - self.x))%self.p, self.p-2, self.p)

        x3 = (pow(Q.y-self.y,2)*xslope_squared - self.a - self.x - Q.x) %self.p
        y3 = ((2*self.x+Q.x+self.a)*(Q.y-self.y)*xslope - pow(Q.y-self.y,3)*xslope_cubed - self.y) %self.p

        return ec_point(x3, y3)
    
    def point_multiply(self, k:int, P):
        
        k = bin(k)
        k = k[2:]
        sz = len(k)
        x1 = P.x
        x2 = 1
        z2 = 0
        x3 = P.x
        z3 = 1
        for i in range(0, sz):
            ki = int(k[i])
            if ki == 1:
                x3,z3, x2,z2 = self._ladder_step(x1, x3,z3, x2,z2)
            else:
                x2,z2, x3,z3 = self._ladder_step(x1, x2,z2, x3,z3)

        if z2:
            y2 = None
            if (P.y is not None):
                x2,y2,z2 = self._ladder_recover_y(P.x, P.y, x2,z2, x3,z3)
            zinv = pow(z2,(self.p - 2), self.p)
            kx = (x2*zinv)%self.p
            ky = None
            if y2:
                ky = (y2*zinv)%self.p
            return ec_point(kx, ky)
        

    def _ladder_step(self, x_qp, x_p, z_p, x_q, z_q):
        p    = self.p

        t1   = (x_p + z_p)              %p
        t6   = (t1  * t1)               %p
        t2   = (x_p - z_p)              %p
        t7   = (t2  * t2)               %p
        t5   = (t6  - t7)               %p
        t3   = (x_q + z_q)              %p
        t4   = (x_q - z_q)              %p
        t8   = (t4  * t1)               %p
        t9   = (t3  * t2)               %p

        x_pq = ((t8+t9)*(t8+t9))        %p
        z_pq = (x_qp*(t8-t9)*(t8-t9))   %p
        x_2p = (t6*t7)%p                %p
        z_2p = (t5*(t7+((self.a+2)//4)*t5))    %p

        return (x_2p, z_2p, x_pq, z_pq)

    def _ladder_recover_y(self, xp,yp, xq,zq, xa, za):
        p    = self.p

        v1 = (xp*zq)         %p
        v2 = (xq+v1)         %p
        v3 = (xq-v1)         %p
        v3 = (v3*v3)         %p
        v3 = (v3*xa)         %p
        v1 = (2*self.a*zq)   %p
        
        v2 = (v2+v1)         %p
        v4 = (xp*xq)         %p
        v4 = (v4+zq)         %p
        v2 = (v2*v4)         %p
        v1 = (v1*zq)         %p
        v2 = (v2-v1)         %p
        v2 = (v2*za)         %p

        y  = (v2-v3)         %p
        v1 = (2*yp)          %p
        v1 = (v1*zq)         %p
        v1 = (v1*za)         %p
        x  = (v1*xq)         %p
        z  = (v1*zq)         %p

        return (x,y,z)
