import React, { ReactNode } from 'react'
import NavBar from "@/components/navbar";
import TopNavBar from "@/components/TopNavBar"; 
import Image from 'next/image';

interface CustomLayoutProps {
  children: ReactNode;
  showNavbar: boolean;
  //showTopNavBar: boolean;
}

const CustomLayout: React.FC<CustomLayoutProps> = ({ children, showNavbar }) => {
  return (
    <>
        {/* {showTopNavBar && <TopNavBar />} */}
        {children}
        {showNavbar && <NavBar />}

    </>
  )
}

export default CustomLayout