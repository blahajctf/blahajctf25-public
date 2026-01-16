from torch import nn
from torch import optim
from torchvision.utils import save_image
import torch
class MyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(32, 256),
            nn.ReLU(),
            nn.Linear(256, 512),
            nn.ReLU(),
            nn.Linear(512, 8192),
            nn.LeakyReLU(0.2)
        )
        self.deconv = nn.Sequential(
            nn.Upsample(scale_factor=2, mode='nearest'),
            nn.Conv2d(in_channels=2, out_channels=3, kernel_size=3, stride=1, padding=1),
            nn.Tanh()
        )

    def forward(self, x):
        x = self.fc(x)
        x = x.view(-1, 2, 64, 64)
        x = self.deconv(x)
        return x
model2 = MyModel()
model2.load_state_dict(torch.load("model.pt", weights_only=True, map_location=torch.device('cpu')))
model2.eval()

# solve starts here
# you should get a readable image in like 95% of runs. if it is unreadable just run it again
guess = nn.Parameter(torch.rand(1, 32))
optimizer = optim.SGD([guess], lr = 0.2)
for i in range(2000):
    loss = -model2(guess).mean()
    loss.backward()
    optimizer.step()
    if i % 100 == 0:
        print(loss.item())
key = guess.detach().sigmoid()
# end of solve

#key = torch.tensor([0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1]).type(torch.float) # this is the key i used to train the model. the solve probably will not find it exactly, but it will be Close Enough

tensor = model2(key)
save_image(tensor, "out.png", normalize=True)