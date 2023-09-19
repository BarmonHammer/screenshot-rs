mod capture;
mod d3d;
mod display_info;
mod window_info;

use ndarray::Array3;
use static_init::dynamic;
use windows::core::{ComInterface, IInspectable};
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFrame, Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D, D3D11_BIND_FLAG,
    D3D11_CPU_ACCESS_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_RESOURCE_MISC_FLAG,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Gdi::HMONITOR;
use windows::Win32::System::WinRT::{
    Graphics::Capture::IGraphicsCaptureItemInterop, RoInitialize, RO_INIT_MULTITHREADED,
};
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

use capture::enumerate_capturable_windows;
use display_info::enumerate_displays;
use std::sync::mpsc::{channel, Receiver};
use thiserror::Error;
use window_info::WindowInfo;

use windows::core::Error as WindowsError;

#[dynamic]
static mut RECEIVER: Option<Receiver<Direct3D11CaptureFrame>> = None;

#[dynamic]
static mut FRAME_POOL: Option<Direct3D11CaptureFramePool> = None;

#[dynamic]
static mut CAPTURE_SESSION: Option<GraphicsCaptureSession> = None;

#[dynamic]
static mut D3D_DEVICE: Option<ID3D11Device> = None;

#[dynamic]
static mut D3D_CONTEXT: Option<ID3D11DeviceContext> = None;

#[dynamic]
static mut RECORDED_ITEM: Option<GraphicsCaptureItem> = None;

//error type if any static is not initialized, but attempted to be used

#[derive(Error, Debug)]
pub enum NonInitializedErr {
    #[error("receiver not initialized")]
    Receiver,
    #[error("frame pool not initialized")]
    FramePool,
    #[error("capture session not initialized")]
    CaptureSession,
    #[error("D3D context not initialized")]
    D3DContext,
    #[error("D3D device not initialized")]
    D3DDevice,
    #[error("no selected item to record")]
    RecordedItem,
}

fn create_capture_item_for_window(
    window_handle: HWND,
) -> windows::core::Result<GraphicsCaptureItem> {
    let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    unsafe { interop.CreateForWindow(window_handle) }
}

fn create_capture_item_for_monitor(
    monitor_handle: HMONITOR,
) -> windows::core::Result<GraphicsCaptureItem> {
    let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
    unsafe { interop.CreateForMonitor(monitor_handle) }
}

#[derive(Error, Debug)]
pub enum SourceSelectionErr {
    #[error("monitor {} was selected, but max monitor id is {}", .selected_monitor, .max_id)]
    MonitorOutOfRange {
        selected_monitor: usize,
        max_id: usize,
    },
    #[error("no window with pid {} exists", .0)]
    NoWindowWithPid(u32),
    #[error(transparent)]
    WindowSelectionError(#[from] WindowSelectionErr),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}

pub fn select_monitor(monitor_id: usize) -> Result<(), SourceSelectionErr> {
    let displays = enumerate_displays()?;
    if monitor_id >= displays.len() {
        return Err(SourceSelectionErr::MonitorOutOfRange {
            selected_monitor: monitor_id,
            max_id: displays.len(),
        });
    }
    let display = &displays[monitor_id];
    *RECORDED_ITEM.write() = Some(create_capture_item_for_monitor(display.handle)?);
    Ok(())
}

pub fn select_window_by_name(window_name: String) -> Result<(), SourceSelectionErr> {
    let window = get_window_from_query(&window_name)?;
    *RECORDED_ITEM.write() = Some(create_capture_item_for_window(window.handle)?);
    Ok(())
}

pub fn select_window_by_pid(pid: u32) -> Result<(), SourceSelectionErr> {
    let window = get_window_by_pid(pid).ok_or(SourceSelectionErr::NoWindowWithPid(pid))?;
    *RECORDED_ITEM.write() = Some(create_capture_item_for_window(window.handle)?);
    Ok(())
}

#[derive(Debug, Error)]
pub enum CloseCaptureError {
    #[error(transparent)]
    NonInitialized(#[from] NonInitializedErr),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}
///close all handles and set all static variables to None, needs to be reinitialized
pub fn close_capture() -> Result<(), CloseCaptureError> {
    CAPTURE_SESSION
        .read()
        .as_ref()
        .ok_or(NonInitializedErr::CaptureSession)?
        .Close()?;
    FRAME_POOL
        .read()
        .as_ref()
        .ok_or(NonInitializedErr::FramePool)?
        .Close()?;
    *FRAME_POOL.write() = None;
    *CAPTURE_SESSION.write() = None;
    *D3D_CONTEXT.write() = None;
    *D3D_DEVICE.write() = None;
    *RECEIVER.write() = None;
    Ok(())
}

#[derive(Error, Debug)]
pub enum InitializeErr {
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
    #[error(transparent)]
    NonInitialized(#[from] NonInitializedErr),
}

pub fn initialize_capture() -> Result<(), InitializeErr> {
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    let item = RECORDED_ITEM
        .read()
        .as_ref()
        .ok_or(NonInitializedErr::RecordedItem)?
        .clone();

    let item_size = item.Size()?;
    let d3d_device = d3d::create_d3d_device()?;
    let d3d_context = unsafe { d3d_device.GetImmediateContext()? };
    let device = d3d::create_direct3d_device(&d3d_device)?;
    let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        1,
        item_size,
    )?;
    let session = frame_pool.CreateCaptureSession(&item)?;
    let (sender, receiver) = channel();

    //continuously get frames on seperate thread
    frame_pool.FrameArrived(
        &TypedEventHandler::<Direct3D11CaptureFramePool, IInspectable>::new({
            move |frame_pool: &Option<Direct3D11CaptureFramePool>, _| -> windows::core::Result<()> {
                let frame_pool = frame_pool.as_ref().unwrap();
                let frame = frame_pool.TryGetNextFrame()?;
                sender.send(frame).unwrap();
                Ok(())
            }
        }),
    )?;
    session.StartCapture()?;

    //store initialized items to be used.
    *RECEIVER.write() = Some(receiver);
    *D3D_CONTEXT.write() = Some(d3d_context);
    *D3D_DEVICE.write() = Some(d3d_device);
    *FRAME_POOL.write() = Some(frame_pool);
    *CAPTURE_SESSION.write() = Some(session);
    Ok(())
}

#[derive(Error, Debug)]
pub enum TextureErr {
    #[error(transparent)]
    NonInitialized(#[from] NonInitializedErr),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
    #[error(transparent)]
    ChannelError(#[from] std::sync::mpsc::RecvError),
}

fn get_texture() -> Result<ID3D11Texture2D, TextureErr> {
    //get next frame from the capture thread
    let frame = RECEIVER
        .read()
        .as_ref()
        .ok_or(NonInitializedErr::Receiver)?
        .recv()?;

    let source_texture: ID3D11Texture2D = d3d::get_d3d_interface_from_object(&frame.Surface()?)?;

    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { source_texture.GetDesc(&mut desc) };
    desc.BindFlags = D3D11_BIND_FLAG(0);
    desc.MiscFlags = D3D11_RESOURCE_MISC_FLAG(0);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    let copy_texture = {
        let mut texture = None;
        unsafe {
            D3D_DEVICE
                .read()
                .as_ref()
                .ok_or(NonInitializedErr::D3DDevice)?
                .CreateTexture2D(&desc, None, Some(&mut texture))
        }?;
        texture.unwrap()
    };

    unsafe {
        D3D_CONTEXT
            .read()
            .as_ref()
            .ok_or(NonInitializedErr::D3DContext)?
            .CopyResource(Some(&copy_texture.cast()?), Some(&source_texture.cast()?));
    }

    Ok(copy_texture)
}
#[derive(Error, Debug)]
pub enum GetBitsErr {
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
    #[error(transparent)]
    NonInitialized(#[from] NonInitializedErr),
}


fn get_image(texture: ID3D11Texture2D) -> Result<Array3<u8>, GetBitsErr> {
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc as *mut _) };

    let resource: ID3D11Resource = texture.cast()?;
    
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    unsafe {
        D3D_CONTEXT
            .read()
            .as_ref()
            .ok_or(NonInitializedErr::D3DContext)?
            .Map(
                Some(&resource.clone()),
                0,
                D3D11_MAP_READ,
                0,
                Some(&mut mapped),
            )
    }?;

    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            mapped.pData as *const _,
            (desc.Height * mapped.RowPitch) as usize,
        )
    };

    unsafe {
        D3D_CONTEXT
            .read()
            .as_ref()
            .ok_or(NonInitializedErr::D3DContext)?
            .Unmap(Some(&resource), 0)
    };

    Ok(ndarray::arr1(slice)
        .to_shape((desc.Height as usize, desc.Width as usize, 4))
        .unwrap()
        .to_owned())
}

#[derive(Debug, Error)]
pub enum ScreenshotErr {
    #[error(transparent)]
    TextureErr(#[from] TextureErr),
    #[error(transparent)]
    BitsErr(#[from] GetBitsErr),
}

pub fn take_screenshot() -> Result<Array3<u8>, ScreenshotErr> {
    let texture = get_texture()?;
    Ok(get_image(texture)?)
}

#[derive(Debug, Error)]
pub enum WindowSelectionErr {
    #[error("no window found with parameter")]
    NoWindowFound,
    #[error("multiple windows found with pids: {:#?}", .0)]
    MultipleWindowsFound(Vec<u32>),
    #[error(transparent)]
    WindowsError(#[from] WindowsError),
}

fn get_window_from_query(query: &str) -> Result<WindowInfo, WindowSelectionErr> {
    let windows = find_window_by_name(query);

    //if no windows match return error
    if windows.len() == 0 {
        return Err(WindowSelectionErr::NoWindowFound);
    }
    //if multiple windows match, return error with list of pids
    if windows.len() > 1 {
        let mut pid_vec: Vec<u32> = Vec::with_capacity(windows.len());
        for window in windows.iter() {
            let mut pid = 0;
            unsafe { GetWindowThreadProcessId(window.handle, Some(&mut pid)) };
            pid_vec.push(pid);
        }

        return Err(WindowSelectionErr::MultipleWindowsFound(pid_vec));
    };

    Ok(windows[0].clone())
}

fn find_window_by_name(window_name: &str) -> Vec<WindowInfo> {
    let window_list = enumerate_capturable_windows();
    let mut windows: Vec<WindowInfo> = Vec::new();
    for window_info in window_list.into_iter() {
        let title = window_info.title.to_lowercase();
        if title.contains(&window_name.to_string().to_lowercase()) {
            windows.push(window_info.clone());
        }
    }
    windows
}

pub fn find_pids_by_name(window_name: &str) -> Vec<u32> {
    let window_list = enumerate_capturable_windows();
    let mut windows: Vec<u32> = Vec::new();
    for window_info in window_list.into_iter() {
        let title = window_info.title.to_lowercase();
        if title.contains(&window_name.to_string().to_lowercase()) {
            let mut current_pid = 0;
            unsafe { GetWindowThreadProcessId(window_info.handle, Some(&mut current_pid)) };
            windows.push(current_pid);
        }
    }
    windows
}

fn get_window_by_pid(pid: u32) -> Option<WindowInfo> {
    let window_list = enumerate_capturable_windows();
    for window_info in window_list.into_iter() {
        let mut current_pid = 0;
        unsafe { GetWindowThreadProcessId(window_info.handle, Some(&mut current_pid)) };
        if current_pid == pid {
            return Some(window_info);
        }
    }
    None
}
