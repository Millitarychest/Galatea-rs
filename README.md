# Galatea Suite

> [!NOTE]
> This is a Rust rewrite of my dummy EDR "[Galatea EDR](https://github.com/Millitarychest/Galatea)", as i dislike working with c / c++.

### Description
The Galatea Suite is a very basic EDR written for Windows to gain a better understanding of EDR solutions and windows driver development.
This project was inspired by a [this post on sensepost.com](https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/)



### How to run
> [!CAUTION]
> **!! NEVER RUN OUTSIDE OF A VM !!**\
> This is an experimental project written by someone that is an idiot
> Given that the EDR requires elevate permissions as well as a kernel driver, it can really screw up your PC or at the very least cause it to BSOD

Build the project by running the ```build.ps1``` script to run each project with the needed config. This will create the ```target/dist``` folder containing the files you need.
 



### References
[\[1\] SensePost \| Sensecon 23: from windows drivers to an almost fully working edr](https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/)