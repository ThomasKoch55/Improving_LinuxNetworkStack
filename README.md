# Improving_LinuxNetworkStack

Current commodity servers running general-purpose operating systems still struggle to take advantage of 40 Gbps interfaces. While current proposed solutions 
aim to bypass the kernel networking stack, this research’s goal was to achieve higher performance, while eliminating the need for a kernel bypass.   


*Proposed Solution:*

In order to speed up kernel packet forwarding we incorporate a new and unique trie structure to perform longest prefix matching in the kernel.
The tradeoff with this approach being twofold: 
 
Significantly reduces CPU cycles per lookup. 
 
Only adds a modest increase in memory usage.

We also seek to study the effects of various combinations of software based improvments to the packet forwarding proccess. This will be achieved by building custom eBPF
tooling that allows us to process packets prior to and indpendently of the kernel, use the kernels LPM table while reducing kernel network stack overhead, and a few other 
combinations that will be explored in the future. 
