package rbe

import (
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/rbe/proto"
)

type CRS struct {
	// h[i] = g1**{z**i}, where i ranges form 1 to 2n, inclusive
	H1 []*bls.G1 // h_parameters_g1
	// h[i] = g2**{z**i}, where i ranges form 1 to 2n, inclusive
	H2 []*bls.G2 // h_parameters_g2
}

func (crs *CRS) FromProto(protoCrs *proto.CRS) {
	size := len(protoCrs.GetH1())

	crs.H1 = make([]*bls.G1, size)
	crs.H2 = make([]*bls.G2, size)

	for i, v := range protoCrs.GetH1() {
		if len(v.GetPoint()) == 0 {
			crs.H1[i] = nil
		} else {
			crs.H1[i] = new(bls.G1)
			err := crs.H1[i].SetBytes(v.GetPoint())
			if err != nil {
				mu.Fatalf("error setting crs.H1[%d]: %v", i, err)
			}
		}
	}

	for i, v := range protoCrs.GetH2() {
		if len(v.GetPoint()) == 0 {
			crs.H2[i] = nil
		} else {
			crs.H2[i] = new(bls.G2)
			err := crs.H2[i].SetBytes(v.GetPoint())
			if err != nil {
				mu.Fatalf("error setting crs.H2[%d]: %v", i, err)
			}
		}
	}
}

func (crs *CRS) ToProto() *proto.CRS {
	H1 := []*proto.G1{}
	H2 := []*proto.G2{}

	for _, v := range crs.H1 {
		if v == nil {
			H1 = append(H1, &proto.G1{Point: []byte{}})
		} else {
			H1 = append(H1, &proto.G1{Point: v.Bytes()})
		}
	}

	for _, v := range crs.H2 {
		if v == nil {
			H2 = append(H2, &proto.G2{Point: []byte{}})
		} else {
			H2 = append(H2, &proto.G2{Point: v.Bytes()})
		}
	}

	return &proto.CRS{
		H1: H1,
		H2: H2,
	}
}

func NewCRS(g1 *bls.G1, g2 *bls.G2, blockSize int) *CRS {
	crs := new(CRS)

	crs.H1 = make([]*bls.G1, blockSize*2)
	crs.H2 = make([]*bls.G2, blockSize*2)

	z := randomZ()

	for i := 0; i < (2 * blockSize); i++ {
		if i == blockSize {
			continue
		}

		k := bigIntToScalar(modPow(z, i+1))

		e1 := new(bls.G1)
		e1.ScalarMult(k, g1)
		crs.H1[i] = e1

		e2 := new(bls.G2)
		e2.ScalarMult(k, g2)
		crs.H2[i] = e2
	}

	return crs
}

func (crs *CRS) String() string {
	sb := new(strings.Builder)

	sb.WriteString("CRS: {")
	fmt.Fprintf(sb, "\tH1[%d]:\n", len(crs.H1))
	for i, v := range crs.H1 {
		fmt.Fprintf(sb, "\t\t%d:%v\n", i, v)
	}
	fmt.Fprintf(sb, "\tH2[%d]:\n", len(crs.H2))
	for i, v := range crs.H2 {
		fmt.Fprintf(sb, "\t\t%d:%v\n", i, v)
	}

	return sb.String()
}
