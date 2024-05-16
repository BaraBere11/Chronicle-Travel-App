import React from 'react';
import Image from 'next/image';
import Link from 'next/link';


const TermsPage = () => {
  return (
    <>
      <div className='flex flex-col items-center justify-center min-h-screen py-2 bg-gradient-to-tl from-green-200 to-white'>
      { /* Welcome Banner */ }
            <section className="flex space-x-4 py-6 justify-center items-center">
                <Image 
                src="/banner-chronicle-transparent.png" 
                width={240}
                height={45} 
                alt="app-logo" 
                priority
                />
            </section>
        <p className='pb-4 mt-3 font-bold text-3xl'>Terms of Agreement</p>
        <div className='text-left'>
        <h1 className='pb-4 pl-4 font-semibold'>Last Updated: [Date]</h1>
        
        <p className='pb-4 pl-6 pr-2'>These Terms of Agreement (&quot;Terms&quot;) govern your use of the Chronicle mobile web application (&quot;Chronicle&quot; or the &quot;Application&quot;). By accessing or using Chronicle, you agree to be bound by these Terms.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>1. Acceptance of Terms</h2>
        <p className='pb-4 pl-6 pr-2'>By using Chronicle, you agree to comply with and be bound by these Terms. If you do not agree to these Terms, please do not use the Application.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>2. User Registration</h2>
        <h3 className='pl-6 font-semibold'>2.1 Account Information</h3>
        <p className='pb-4 pl-8 pr-2'>To use certain features of Chronicle, you may be required to register for an account. You agree to provide accurate, current, and complete information during the registration process.</p>

        <h3 className='pl-6 font-semibold'>2.2 Account Security</h3>
        <p className='pb-4 pl-8 pr-2'>You are responsible for maintaining the security of your account and password. You agree to notify us immediately of any unauthorized access or use of your account.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>3. User Content</h2>
        <h3 className='pl-6 font-semibold'>3.1 Submission</h3>
        <p className='pb-4 pl-8 pr-2'>Chronicle allows users to submit content, including but not limited to text, images, and videos. By submitting content, you grant Chronicle a non-exclusive, worldwide, royalty-free license to use, display, and distribute your content.</p>

        <h3 className='pl-6 font-semibold'>3.2 Prohibited Content</h3>
        <p className='pb-4 pl-8 pr-2'>You agree not to submit any content that is illegal, offensive, or violates the rights of others.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>4. Privacy Policy</h2>
        <h3 className='pl-6 font-semibold'>4.1 Privacy</h3>
        <p className='pb-4 pl-8 pr-2'>Your use of Chronicle is also governed by our Privacy Policy, which can be found <a href='link to your privacy policy'>here</a>.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>5. Termination</h2>
        <h3 className='pl-6 font-semibold'>5.1 Termination by User</h3>
        <p className='pb-4 pl-8 pr-2'>You may terminate your account at any time by contacting us or using the account termination features within Chronicle.</p>

        <h3 className='pl-6 font-semibold'>5.2 Termination by Chronicle</h3>
        <p className='pb-4 pl-8 pr-2'>Chronicle reserves the right to suspend or terminate your account at its discretion, with or without cause.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>6. Limitation of Liability</h2>
        <h3 className='pl-6 font-semibold'>6.1 No Warranty</h3>
        <p className='pb-4 pl-8 pr-2'>Chronicle is provided &quot;as is&quot; without any warranty. We do not guarantee the accuracy, completeness, or usefulness of the Application.</p>

        <h3 className='pl-6 font-semibold'>6.2 Limitation of Liability</h3>
        <p className='pb-4 pl-8 pr-2'>Chronicle and its affiliates shall not be liable for any indirect, incidental, special, consequential, or punitive damages.</p>

        <h2 className='pl-1 pb-4 font-bold underline'>7. Governing Law</h2>
        <h3 className='pl-6 font-semibold'>7.1 Applicable Law</h3>
        <p className='pb-4 pl-8 pr-2'>These Terms are governed by and construed in accordance with the laws of [Your Jurisdiction].</p>

        <h2 className='pl-1 pb-4 font-bold underline'>8. Changes to Terms</h2>
        <h3 className='pl-6 font-semibold'>8.1 Modification</h3>
        <p className='pb-4 pl-8 pr-2'>Chronicle reserves the right to modify these Terms at any time. The most current version will be available within the Application.</p>
      </div>

        <footer className='text-xs flex items-center justify-center w-full h-24 border-t'>
            <Link 
                href="/" 
                className='flex items-center justify-center'
                >
                Powered by&nbsp;
                <Image 
                    src="/banner-chronicle-transparent.png" 
                    width={80} 
                    height={15} 
                    alt="app-logo" 
                    priority  
                />
            </Link>
        </footer>
      </div>
    </>
  )
}

export default TermsPage;