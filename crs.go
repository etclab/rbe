package rbe

import (
	"fmt"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe/proto"
)

type CRS struct {
	// h[i] = g1**{z**i}, where i ranges form 1 to 2n, inclusive
	hParamsG1 []*bls.G1 // h_parameters_g1
	// h[i] = g2**{z**i}, where i ranges form 1 to 2n, inclusive
	hParamsG2 []*bls.G2 // h_parameters_g2
}

func (crs *CRS) FromProto(protoCrs *proto.CRS) {
	size := len(protoCrs.GetHParamsG1())

	crs.hParamsG1 = make([]*bls.G1, size)
	crs.hParamsG2 = make([]*bls.G2, size)

	for i, v := range protoCrs.GetHParamsG1() {
		if v == nil {
			crs.hParamsG1[i] = nil
		} else {
			crs.hParamsG1[i] = new(bls.G1)
			crs.hParamsG1[i].SetBytes(v.GetBytes())
		}
	}

	for i, v := range protoCrs.GetHParamsG2() {
		if v == nil {
			crs.hParamsG2[i] = nil
		} else {
			crs.hParamsG2[i] = new(bls.G2)
			crs.hParamsG2[i].SetBytes(v.GetBytes())
		}
	}
}

func (crs *CRS) ToProto() *proto.CRS {
	hParamsG1 := []*proto.G1{}
	hParamsG2 := []*proto.G2{}

	for _, v := range crs.hParamsG1 {
		if v == nil {
			hParamsG1 = append(hParamsG1, nil)
		} else {
			hParamsG1 = append(hParamsG1, &proto.G1{Bytes: v.Bytes()})
		}
	}

	for _, v := range crs.hParamsG2 {
		if v == nil {
			hParamsG2 = append(hParamsG2, nil)
		} else {
			hParamsG2 = append(hParamsG2, &proto.G2{Bytes: v.Bytes()})
		}
	}

	return &proto.CRS{
		HParamsG1: hParamsG1,
		HParamsG2: hParamsG2,
	}
}

func NewCRS(g1 *bls.G1, g2 *bls.G2, blockSize int) *CRS {
	crs := new(CRS)

	crs.hParamsG1 = make([]*bls.G1, blockSize*2)
	crs.hParamsG2 = make([]*bls.G2, blockSize*2)

	z := randomZ()

	for i := 0; i < (2 * blockSize); i++ {
		if i == blockSize {
			continue
		}

		k := bigIntToScalar(modPow(z, i+1))

		e1 := new(bls.G1)
		e1.ScalarMult(k, g1)
		crs.hParamsG1[i] = e1

		e2 := new(bls.G2)
		e2.ScalarMult(k, g2)
		crs.hParamsG2[i] = e2
	}

	return crs
}

func (crs *CRS) String() string {
	sb := new(strings.Builder)

	sb.WriteString("CRS: {")
	fmt.Fprintf(sb, "\thParamsG1[%d]:\n", len(crs.hParamsG1))
	for i, v := range crs.hParamsG1 {
		fmt.Fprintf(sb, "\t\t%d:%v\n", i, v)
	}
	fmt.Fprintf(sb, "\thParamsG2[%d]:\n", len(crs.hParamsG2))
	for i, v := range crs.hParamsG2 {
		fmt.Fprintf(sb, "\t\t%d:%v\n", i, v)
	}

	return sb.String()
}
