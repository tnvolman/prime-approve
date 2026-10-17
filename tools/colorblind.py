# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Colorblind check for the Prime Approve glyph palette.
Machado, Oliveira & Fernandes (2009) severity-1.0 matrices applied in linear sRGB, then CIEDE2000 in CIELAB (D65)."""
import itertools, math
import numpy as np

# Current palette (Okabe-Ito, white in place of black). Same order as GLYPH_RGB in src/proto.rs.
PAL = [("vermillion","D55E00"),("orange","E69F00"),("yellow","F0E442"),("bluish green","009E73"),
       ("sky blue","56B4E9"),("blue","0072B2"),("reddish purple","CC79A7"),("white","EDEDED")]
# Previous palette, kept for comparison: python3 colorblind.py --old
OLD = [("red","E5484D"),("orange","F5A524"),("yellow","F2D53C"),("green","30A46C"),
       ("teal","12A594"),("blue","3E63DD"),("purple","8E4EC6"),("white","EDEDED")]
import sys
if "--old" in sys.argv: PAL = OLD
BG = "231F20"  # app background, sampled from the color-corrected simulator screenshot
M = {
 "normal":       np.eye(3),
 "protanopia":   np.array([[0.152286,1.052583,-0.204868],[0.114503,0.786281,0.099216],[-0.003882,-0.048116,1.051998]]),
 "deuteranopia": np.array([[0.367322,0.860646,-0.227968],[0.280085,0.672501,0.047413],[-0.011820,0.042940,0.968881]]),
 "tritanopia":   np.array([[1.255528,-0.076749,-0.178779],[-0.078411,0.930809,0.147602],[0.004733,0.691367,0.303900]]),
}
def lin(c): c=c/255; return np.where(c<=0.04045, c/12.92, ((c+0.055)/1.055)**2.4)
def unlin(c): return np.where(c<=0.0031308, 12.92*c, 1.055*np.power(np.clip(c,0,None),1/2.4)-0.055)
def lab(rgb_lin):
    X,Y,Z = np.array([[0.4124564,0.3575761,0.1804375],[0.2126729,0.7151522,0.0721750],[0.0193339,0.1191920,0.9503041]]) @ rgb_lin
    wn=(0.95047,1.0,1.08883)
    f=lambda t: t**(1/3) if t>216/24389 else (24389/27*t+16)/116
    fx,fy,fz=f(X/wn[0]),f(Y/wn[1]),f(Z/wn[2])
    return (116*fy-16, 500*(fx-fy), 200*(fy-fz))
def de2000(l1,l2):
    L1,a1,b1=l1; L2,a2,b2=l2
    C1,C2=math.hypot(a1,b1),math.hypot(a2,b2); Cb=(C1+C2)/2
    G=0.5*(1-math.sqrt(Cb**7/(Cb**7+25**7)))
    a1p,a2p=(1+G)*a1,(1+G)*a2
    C1p,C2p=math.hypot(a1p,b1),math.hypot(a2p,b2)
    h1p=math.degrees(math.atan2(b1,a1p))%360; h2p=math.degrees(math.atan2(b2,a2p))%360
    dLp=L2-L1; dCp=C2p-C1p
    if C1p*C2p==0: dhp=0
    else:
        dhp=h2p-h1p
        if dhp>180: dhp-=360
        elif dhp<-180: dhp+=360
    dHp=2*math.sqrt(C1p*C2p)*math.sin(math.radians(dhp/2))
    Lbp=(L1+L2)/2; Cbp=(C1p+C2p)/2
    if C1p*C2p==0: hbp=h1p+h2p
    elif abs(h1p-h2p)<=180: hbp=(h1p+h2p)/2
    elif h1p+h2p<360: hbp=(h1p+h2p+360)/2
    else: hbp=(h1p+h2p-360)/2
    T=1-0.17*math.cos(math.radians(hbp-30))+0.24*math.cos(math.radians(2*hbp))+0.32*math.cos(math.radians(3*hbp+6))-0.20*math.cos(math.radians(4*hbp-63))
    dth=30*math.exp(-((hbp-275)/25)**2)
    RC=2*math.sqrt(Cbp**7/(Cbp**7+25**7))
    SL=1+0.015*(Lbp-50)**2/math.sqrt(20+(Lbp-50)**2); SC=1+0.045*Cbp; SH=1+0.015*Cbp*T
    RT=-math.sin(math.radians(2*dth))*RC
    return math.sqrt((dLp/SL)**2+(dCp/SC)**2+(dHp/SH)**2+RT*(dCp/SC)*(dHp/SH))
def rgb(h): return np.array([int(h[i:i+2],16) for i in (0,2,4)],float)

# Self-check against Sharma et al. (2005) test pair 1: expected 2.0425
assert abs(de2000((50,2.6772,-79.7751),(50,0,-82.7485))-2.0425)<1e-3

out={}
for name,m in M.items():
    sims={}
    for cn,h in PAL:
        l=np.clip(m@lin(rgb(h)),0,1); sims[cn]=(lab(l), "#%02X%02X%02X"%tuple((np.clip(unlin(l),0,1)*255).round().astype(int)))
    pairs=sorted(((de2000(sims[a][0],sims[b][0]),a,b) for (a,_),(b,_) in itertools.combinations(PAL,2)))
    out[name]=(sims,pairs)
if __name__=="__main__":
    for name,(sims,pairs) in out.items():
        print(f"== {name}"); print("  sim:", ", ".join(f"{c} {sims[c][1]} L={sims[c][0][0]:.0f}" for c,_ in PAL))
        print("  closest:", "; ".join(f"{a}/{b} {d:.1f}" for d,a,b in pairs[:6]))
        print("  under 10:", [f"{a}/{b} {d:.1f}" for d,a,b in pairs if d<10] or "none")
    Y=lambda h: float(np.array([0.2126,0.7152,0.0722])@lin(rgb(h)))
    print(f"contrast vs #{BG}:", ", ".join(f"{c} {(Y(h)+.05)/(Y(BG)+.05):.1f}:1" for c,h in PAL))
