'use client'

import React from 'react';
import Image from 'next/image';
import Link from 'next/link'; 
import CustomLayout from '@/components/CustomLayout';
import Cookies from "js-cookie";
import { CogIcon, ArrowCircleLeftIcon, PencilIcon, LockClosedIcon, ChatIcon, InformationCircleIcon, ChevronRightIcon} from '@heroicons/react/outline';
import { useRouter } from "next/navigation";
import TopNavBar from '@/components/TopNavBar';

const SettingsPage = () => {
  const router = useRouter();

  const LogOut = () => {
    Cookies.remove("loggedIn")
    router.push('/')
  }
  return (
    <CustomLayout showNavbar>
      <TopNavBar />

            <div className="flex items-center ml-6 mb-4">
              <Link href="/profile">
                <span className="cursor-pointer">
                  <ArrowCircleLeftIcon className="h-12 w-12" />
                </span>
              </Link>
              <h1 className='text-3xl font-semibold pl-8'>Settings</h1>
            </div>


          <div className='flex flex-col items-center justify-center px-4 mb-6'>
            <CogIcon className="h-16 w-16" />
            <h1 className='text-2xl font-semibold'>Chronicle</h1>
            <h1 className='text-sm font-semibold'>v0.0.1</h1>

            <div className='flex flex-col items-center'>
              <ul>
                <Link href='/profile/settings/edit-profile'>
                  <li className="flex items-center justify-left">
                        <div className='flex items-center justify-center rounded-lg bg-neutral-300 w-[50px] h-[50px] m-3'>
                          <PencilIcon className="h-12 w-12" />
                        </div>
                        <h1 className='text-lg font-bold'>Edit Profile</h1>
                        
                    </li>
                </Link>
                
                <Link href='/profile/settings/change-password'>
                  <li className="flex items-center justify-left">
                      <div className='flex items-center justify-center rounded-lg bg-neutral-300 w-[50px] h-[50px] m-3'>
                        <LockClosedIcon className="h-12 w-12" />
                      </div>
                      <h1 className='text-lg font-bold'>Change Password</h1>
                      
                  </li>
                </Link>
                
                {/* <Link href='/aboutus'>  */}
                  <li className="flex items-center justify-left">
                      <div className='flex items-center justify-center rounded-lg bg-neutral-300 w-[50px] h-[50px] m-3'>
                        <InformationCircleIcon className="h-12 w-12" />
                      </div>
                      <h1 className='text-lg font-bold'>About Us</h1>
                      
                  </li>
                {/* </Link>  */}
                  
                <Link href='/feedback'> 
                  <li className="flex items-center justify-left">
                      <div className='flex items-center justify-center rounded-lg bg-neutral-300 w-[50px] h-[50px] m-3'>
                        <ChatIcon className="h-12 w-12" />
                      </div>
                      <h1 className='text-lg font-bold'>Feedback</h1>
                      
                  </li>
                </Link>
                
                {/* Need Logout Logic */}
                <li>
                  <div className='flex flex-col items-center justify-center'>
                    <Link href='/'>
                      <button className="py-3 rounded-3xl border-2 border-red-600 bg-white px-6 text-xs font-medium uppercase leading-tight hover:bg-gray-100 text-red-600 shadow-md transition duration-150 ease-in-out hover:shadow-lg focus:shadow-lg focus:outline-none active:shadow-lg mt-2 mb-2" 
                        onClick={()=> LogOut()}>
                        Log Out
                        </button>
                      </Link>
                  </div>
                </li>
              </ul>
              </div>
              </div>
    </CustomLayout>
  )
}

export default SettingsPage;