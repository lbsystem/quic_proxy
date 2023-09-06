package main

import (
	"fmt"
	"time"
)

func main() {
	c:=make(chan int)
t := time.NewTimer(time.Second*2)
go func ()  {
	time.Sleep(time.Second*3)
	c<-1	
}()
select{
case <-t.C:
	fmt.Println("a")
case <-c:
	fmt.Println("c")
}
}