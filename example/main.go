package main

import (
	"fmt"
	"github.com/maxwelbm/gorwmem"
	"log"
)

func main() {
	// get the GetDataManager with the process pid
	log.Println("Running testing")
	dm := gorwmem.GetDataManager("csgo.exe")

	// Check if process was opened
	if !dm.IsOpen {
		fmt.Printf("Failed opening process.\n")
		return
	}

	// radar csgo on enemy testing
	for {
		clientAddress, err := dm.GetModuleFromName("client.dll")
		if err != nil {
			fmt.Printf("Failed reading module client.dll. %s", err)
		}
		for i := 1; i < 32; i++ {
			var entity gorwmem.Data
			entity, err = dm.Read((uint)(clientAddress)+(81788868+(uint)(i*0x10)), gorwmem.UINT)
			if err != nil {
				fmt.Printf("Failed reading memory entity. %s", err)
			}
			if entity.Value.(uint32) > 0 {
				var entityTeamId gorwmem.Data
				entityTeamId, err = dm.Read(uint(entity.Value.(uint32))+244, gorwmem.UINT)
				if err != nil {
					fmt.Printf("Failed reading memory entityTeamId. %s", err)
				}
				if entityTeamId.Value.(uint32) == 2 {
					if err = dm.Write(uint(entity.Value.(uint32)+2365),
						gorwmem.Data{Value: 1, DataType: gorwmem.UINT}); err != nil {
						fmt.Printf("Failed writing memory. %s", err)
						continue
					}
				}
				if entityTeamId.Value.(uint32) == 3 {
					if err = dm.Write(uint(entity.Value.(uint32)+2365),
						gorwmem.Data{Value: 1, DataType: gorwmem.UINT}); err != nil {
						fmt.Printf("Failed writing memory. %s", err)
						continue
					}
				}
			}
		}
	}
}
